use alloy_consensus::{
    BlobTransactionValidationError, BlockHeader, EnvKzgSettings, SignableTransaction, Transaction,
    TxEip1559, TxReceipt,
};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_eips::{eip4844::kzg_to_versioned_hash, eip7685::RequestsOrHash};
use alloy_rpc_types_beacon::relay::{
    BidTrace, BuilderBlockValidationRequest, BuilderBlockValidationRequestV2,
    BuilderBlockValidationRequestV3, BuilderBlockValidationRequestV4,
};
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use alloy_rpc_types_engine::{
    BlobsBundleV1, CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    PraguePayloadFields,
};
use alloy_rpc_types_engine::{ExecutionPayloadV2, ExecutionPayloadV3};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use bytes::Bytes;
use core::fmt;
use dashmap::DashSet;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{core::RpcResult, types::ErrorObject};
use reth_ethereum::evm::primitives::EvmError;
use reth_ethereum::evm::primitives::block::BlockExecutor;
use reth_ethereum::evm::primitives::execute::{BlockBuilder, ExecutorTx};
use reth_ethereum::{
    chainspec::EthereumHardforks,
    consensus::{ConsensusError, FullConsensus},
    evm::{
        primitives::{Evm, block::BlockExecutionError, execute::Executor},
        revm::{cached::CachedReads, database::StateProviderDatabase},
    },
    node::core::rpc::result::{internal_rpc_err, invalid_params_rpc_err},
    primitives::{
        GotExpected, RecoveredBlock, SealedBlock, SealedHeaderFor, SignedTransaction,
        constants::GAS_LIMIT_BOUND_DIVISOR,
    },
    provider::{BlockExecutionOutput, ChainSpecProvider, ProviderError},
    rpc::eth::utils::recover_raw_transaction,
    storage::{BlockReaderIdExt, StateProviderFactory},
};
use reth_metrics::{Metrics, metrics::Gauge};
use reth_node_builder::{
    Block, BlockBody, ConfigureEvm, NewPayloadError, NextBlockEnvAttributes, NodePrimitives,
    PayloadValidator,
};
use reth_primitives::Recovered;
use reth_tasks::TaskSpawner;
use revm::DatabaseCommit;
use revm::database::states::bundle_state::BundleRetention;
use revm::{Database, database::State};
use revm_primitives::{Address, B256, U256, address};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{
    spawn,
    sync::{RwLock, oneshot},
    time,
};
use tracing::{info, warn};

/// The type that implements the `validation` rpc namespace trait
#[derive(Clone, Debug, derive_more::Deref)]
pub struct ValidationApi<Provider, E: ConfigureEvm> {
    #[deref]
    inner: Arc<ValidationApiInner<Provider, E>>,
}

impl<Provider, E> ValidationApi<Provider, E>
where
    E: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
{
    /// Create a new instance of the [`ValidationApi`]
    pub fn new(
        provider: Provider,
        consensus: Arc<dyn FullConsensus<E::Primitives, Error = ConsensusError>>,
        evm_config: E,
        config: ValidationApiConfig,
        task_spawner: Box<dyn TaskSpawner>,
        payload_validator: Arc<
            dyn PayloadValidator<
                    Block = <E::Primitives as NodePrimitives>::Block,
                    ExecutionData = ExecutionData,
                >,
        >,
    ) -> Self {
        let ValidationApiConfig {
            blacklist_endpoint,
            validation_window,
            merger_private_key,
            relay_fee_recipient,
        } = config;
        let disallow = Arc::new(DashSet::new());

        let merger_signer = merger_private_key
            .parse()
            .expect("Failed to parse merger private key");

        let relay_fee_recipient = relay_fee_recipient
            .parse()
            .expect("Failed to parse relay fee recipient");

        let inner = Arc::new(ValidationApiInner {
            provider,
            consensus,
            payload_validator,
            evm_config,
            disallow: disallow.clone(),
            validation_window,
            cached_state: Default::default(),
            task_spawner,
            metrics: Default::default(),
            merger_signer,
            relay_fee_recipient,
            // Address of `Disperse.app` contract
            // https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150
            distribution_contract: address!("0xD152f549545093347A162Dce210e7293f1452150"),
        });

        inner.metrics.disallow_size.set(inner.disallow.len() as f64);

        // spawn background updater task
        let client = reqwest::Client::new();
        let ep = blacklist_endpoint.clone();
        let dash = disallow.clone();
        let gauge = inner.metrics.disallow_size.clone();
        spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                match client.get(&ep).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(list) = resp.json::<Vec<String>>().await {
                            // build new set then swap
                            dash.clear();
                            for hex in list {
                                if let Ok(b) =
                                    hex.strip_prefix("0x").unwrap_or(&hex).parse::<B256>()
                                {
                                    dash.insert(Address::from_slice(b.as_slice()));
                                }
                            }
                            gauge.set(dash.len() as f64);
                        }
                    }
                    Ok(r) => warn!("Blacklist fetch failed: HTTP {}", r.status()),
                    Err(e) => warn!("Blacklist fetch error: {}", e),
                }
            }
        });

        Self { inner }
    }

    /// Returns the cached reads for the given head hash.
    async fn cached_reads(&self, head: B256) -> CachedReads {
        let cache = self.inner.cached_state.read().await;
        if cache.0 == head {
            cache.1.clone()
        } else {
            Default::default()
        }
    }

    /// Updates the cached state for the given head hash.
    async fn update_cached_reads(&self, head: B256, cached_state: CachedReads) {
        let mut cache = self.inner.cached_state.write().await;
        if cache.0 == head {
            cache.1.extend(cached_state);
        } else {
            *cache = (head, cached_state)
        }
    }
}

impl<Provider, E> ValidationApi<Provider, E>
where
    Provider: BlockReaderIdExt<Header = <E::Primitives as NodePrimitives>::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + StateProviderFactory
        + 'static,
    E: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes> + 'static,
{
    /// Validates the given block and a [`BidTrace`] against it.
    pub async fn validate_message_against_block(
        &self,
        block: RecoveredBlock<<E::Primitives as NodePrimitives>::Block>,
        message: BidTrace,
        _registered_gas_limit: u64,
        apply_blacklist: bool,
        inclusion_list: Option<InclusionList>,
    ) -> Result<(), ValidationApiError> {
        self.validate_message_against_header(block.sealed_header(), &message)?;

        self.consensus.validate_header(block.sealed_header())?;
        self.consensus
            .validate_block_pre_execution(block.sealed_block())?;

        if !self.disallow.is_empty() && apply_blacklist {
            if self.disallow.contains(&block.beneficiary()) {
                return Err(ValidationApiError::Blacklist(block.beneficiary()));
            }
            if self.disallow.contains(&message.proposer_fee_recipient) {
                return Err(ValidationApiError::Blacklist(
                    message.proposer_fee_recipient,
                ));
            }
            for (sender, tx) in block.senders_iter().zip(block.body().transactions()) {
                if self.disallow.contains(sender) {
                    return Err(ValidationApiError::Blacklist(*sender));
                }
                if let Some(to) = tx.to() {
                    if self.disallow.contains(&to) {
                        return Err(ValidationApiError::Blacklist(to));
                    }
                }
            }
        }

        let latest_header = self
            .provider
            .latest_header()?
            .ok_or_else(|| ValidationApiError::MissingLatestBlock)?;

        let parent_header = if block.parent_hash() == latest_header.hash() {
            latest_header
        } else {
            // parent is not the latest header so we need to fetch it and ensure it's not too old
            let parent_header = self
                .provider
                .sealed_header_by_hash(block.parent_hash())?
                .ok_or_else(|| ValidationApiError::MissingParentBlock)?;

            if latest_header
                .number()
                .saturating_sub(parent_header.number())
                > self.validation_window
            {
                return Err(ValidationApiError::BlockTooOld);
            }
            parent_header
        };

        self.consensus
            .validate_header_against_parent(block.sealed_header(), &parent_header)?;
        let parent_header_hash = parent_header.hash();
        let state_provider = self.provider.state_by_block_hash(parent_header_hash)?;

        let mut request_cache = self.cached_reads(parent_header_hash).await;

        let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));

        let mut executor = self.evm_config.batch_executor(cached_db);

        let mut accessed_blacklisted = None;

        let result = executor
            .execute_one(&block)
            .map_err(|e| ValidationApiError::Execution(e.into()))?;

        let state = executor.into_state();

        if !self.disallow.is_empty() && apply_blacklist {
            // Check whether the submission interacted with any blacklisted account by scanning
            // the `State`'s cache that records everything read form database during execution.
            for account in state.cache.accounts.keys() {
                if self.disallow.contains(account) {
                    accessed_blacklisted = Some(*account);
                }
            }
        }

        if let Some(account) = accessed_blacklisted {
            return Err(ValidationApiError::Blacklist(account));
        }

        let output = BlockExecutionOutput {
            state: state.bundle_state.clone(),
            result,
        };

        // Validate inclusion list constraint if provided
        if let Some(inclusion_list) = inclusion_list {
            self.validate_inclusion_list_constraint(&block, state, &inclusion_list)?;
        }

        // update the cached reads
        self.update_cached_reads(parent_header_hash, request_cache)
            .await;

        self.consensus
            .validate_block_post_execution(&block, &output)?;

        self.ensure_payment(&block, &output, &message)?;

        let state_root =
            state_provider.state_root(state_provider.hashed_post_state(&output.state))?;

        if state_root != block.header().state_root() {
            return Err(ConsensusError::BodyStateRootDiff(
                GotExpected {
                    got: state_root,
                    expected: block.header().state_root(),
                }
                .into(),
            )
            .into());
        }

        Ok(())
    }

    fn validate_inclusion_list_constraint<DB>(
        &self,
        block: &RecoveredBlock<<E::Primitives as NodePrimitives>::Block>,
        post_state: State<DB>,
        inclusion_list: &InclusionList,
    ) -> Result<(), ValidationApiError>
    where
        DB: Database,
        <DB as revm::Database>::Error: Send + Sync + 'static,
    {
        // nothing to do if no inclusion‐list entries
        if inclusion_list.txs.is_empty() {
            return Ok(());
        }

        // collect which inclusion‐list hashes appeared in the block
        let mut included_hashes = HashSet::new();
        for tx in block.body().transactions() {
            if let Some(req) = inclusion_list
                .txs
                .iter()
                .find(|t| t.hash.as_slice() == tx.tx_hash().as_slice())
            {
                included_hashes.insert(req.hash);
            }
        }

        // if all requested txs are already in the block, we’re done
        if included_hashes.len() == inclusion_list.txs.len() {
            return Ok(());
        }

        // set up a fresh EVM on top of a cache wrapping the post-block state
        let mut evm = self.evm_config.evm_for_block(post_state, block.header());

        // simulate each missing inclusion‐list tx
        for req in &inclusion_list.txs {
            // skip the ones that actually made it in
            if included_hashes.contains(&req.hash) {
                continue;
            }

            // RLP-decode the raw bytes
            let mut bytes_slice = req.bytes.as_ref();
            let transaction = recover_raw_transaction(&mut bytes_slice)
                .map_err(|_| ValidationApiError::InclusionList)?;

            // execute the tx
            let outcome = evm.transact(transaction);

            // f it succeeded, then this tx *could* have been included but wasn’t → reject
            if outcome.is_ok() {
                return Err(ValidationApiError::InclusionList);
            }
            // otherwise it failed as expected; keep going
        }

        // every missing tx failed in simulation, so constraint is satisfied
        Ok(())
    }

    /// Ensures that fields of [`BidTrace`] match the fields of the [`SealedHeaderFor`].
    fn validate_message_against_header(
        &self,
        header: &SealedHeaderFor<E::Primitives>,
        message: &BidTrace,
    ) -> Result<(), ValidationApiError> {
        if header.hash() != message.block_hash {
            Err(ValidationApiError::BlockHashMismatch(GotExpected {
                got: message.block_hash,
                expected: header.hash(),
            }))
        } else if header.parent_hash() != message.parent_hash {
            Err(ValidationApiError::ParentHashMismatch(GotExpected {
                got: message.parent_hash,
                expected: header.parent_hash(),
            }))
        } else if header.gas_limit() != message.gas_limit {
            Err(ValidationApiError::GasLimitMismatch(GotExpected {
                got: message.gas_limit,
                expected: header.gas_limit(),
            }))
        } else if header.gas_used() != message.gas_used {
            return Err(ValidationApiError::GasUsedMismatch(GotExpected {
                got: message.gas_used,
                expected: header.gas_used(),
            }));
        } else {
            Ok(())
        }
    }

    /// Ensures that the chosen gas limit is the closest possible value for the validator's
    /// registered gas limit.
    ///
    /// Ref: <https://github.com/flashbots/builder/blob/a742641e24df68bc2fc476199b012b0abce40ffe/core/blockchain.go#L2474-L2477>
    fn validate_gas_limit(
        &self,
        registered_gas_limit: u64,
        parent_header: &SealedHeaderFor<E::Primitives>,
        header: &SealedHeaderFor<E::Primitives>,
    ) -> Result<(), ValidationApiError> {
        let max_gas_limit =
            parent_header.gas_limit() + parent_header.gas_limit() / GAS_LIMIT_BOUND_DIVISOR - 1;
        let min_gas_limit =
            parent_header.gas_limit() - parent_header.gas_limit() / GAS_LIMIT_BOUND_DIVISOR + 1;

        let best_gas_limit = std::cmp::max(
            min_gas_limit,
            std::cmp::min(max_gas_limit, registered_gas_limit),
        );

        if best_gas_limit != header.gas_limit() {
            return Err(ValidationApiError::GasLimitMismatch(GotExpected {
                got: header.gas_limit(),
                expected: best_gas_limit,
            }));
        }

        Ok(())
    }

    /// Ensures that the proposer has received [`BidTrace::value`] for this block.
    ///
    /// Firstly attempts to verify the payment by checking the state changes, otherwise falls back
    /// to checking the latest block transaction.
    fn ensure_payment(
        &self,
        block: &SealedBlock<<E::Primitives as NodePrimitives>::Block>,
        output: &BlockExecutionOutput<<E::Primitives as NodePrimitives>::Receipt>,
        message: &BidTrace,
    ) -> Result<(), ValidationApiError> {
        let (mut balance_before, balance_after) =
            if let Some(acc) = output.state.state.get(&message.proposer_fee_recipient) {
                let balance_before = acc
                    .original_info
                    .as_ref()
                    .map(|i| i.balance)
                    .unwrap_or_default();
                let balance_after = acc.info.as_ref().map(|i| i.balance).unwrap_or_default();

                (balance_before, balance_after)
            } else {
                // account might have balance but considering it zero is fine as long as we know
                // that balance have not changed
                (U256::ZERO, U256::ZERO)
            };

        if let Some(withdrawals) = block.body().withdrawals() {
            for withdrawal in withdrawals {
                if withdrawal.address == message.proposer_fee_recipient {
                    balance_before += withdrawal.amount_wei();
                }
            }
        }

        if balance_after >= balance_before + message.value {
            return Ok(());
        }

        let (receipt, tx) = output
            .receipts
            .last()
            .zip(block.body().transactions().last())
            .ok_or(ValidationApiError::ProposerPayment)?;

        if !receipt.status() {
            return Err(ValidationApiError::ProposerPayment);
        }

        if tx.to() != Some(message.proposer_fee_recipient) {
            return Err(ValidationApiError::ProposerPayment);
        }

        if tx.value() != message.value {
            return Err(ValidationApiError::ProposerPayment);
        }

        if !tx.input().is_empty() {
            return Err(ValidationApiError::ProposerPayment);
        }

        if let Some(block_base_fee) = block.header().base_fee_per_gas() {
            if tx.effective_tip_per_gas(block_base_fee).unwrap_or_default() != 0 {
                return Err(ValidationApiError::ProposerPayment);
            }
        }

        Ok(())
    }

    /// Validates the given [`BlobsBundleV1`] and returns versioned hashes for blobs.
    pub fn validate_blobs_bundle(
        &self,
        mut blobs_bundle: BlobsBundleV1,
    ) -> Result<Vec<B256>, ValidationApiError> {
        if blobs_bundle.commitments.len() != blobs_bundle.proofs.len()
            || blobs_bundle.commitments.len() != blobs_bundle.blobs.len()
        {
            return Err(ValidationApiError::InvalidBlobsBundle);
        }

        let versioned_hashes = blobs_bundle
            .commitments
            .iter()
            .map(|c| kzg_to_versioned_hash(c.as_slice()))
            .collect::<Vec<_>>();

        let sidecar = blobs_bundle.pop_sidecar(blobs_bundle.blobs.len());

        sidecar.validate(&versioned_hashes, EnvKzgSettings::default().get())?;

        Ok(versioned_hashes)
    }

    /// Core logic for validating the builder submission v3
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> Result<(), ValidationApiError> {
        let block = self
            .payload_validator
            .ensure_well_formed_payload(ExecutionData {
                payload: ExecutionPayload::V3(request.request.execution_payload),
                sidecar: ExecutionPayloadSidecar::v3(CancunPayloadFields {
                    parent_beacon_block_root: request.parent_beacon_block_root,
                    versioned_hashes: self.validate_blobs_bundle(request.request.blobs_bundle)?,
                }),
            })?;

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            false,
            None,
        )
        .await
    }

    /// Core logic for validating the builder submission v4
    async fn validate_builder_submission_v4(
        &self,
        request: ExtendedValidationRequestV4,
    ) -> Result<(), ValidationApiError> {
        info!(target: "rpc::relay", "Validating builder submission v4 test");
        let block = self
            .payload_validator
            .ensure_well_formed_payload(ExecutionData {
                payload: ExecutionPayload::V3(request.base.request.execution_payload),
                sidecar: ExecutionPayloadSidecar::v4(
                    CancunPayloadFields {
                        parent_beacon_block_root: request.base.parent_beacon_block_root,
                        versioned_hashes: self
                            .validate_blobs_bundle(request.base.request.blobs_bundle)?,
                    },
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(
                            request.base.request.execution_requests.to_requests(),
                        ),
                    },
                ),
            })?;

        self.validate_message_against_block(
            block,
            request.base.request.message,
            request.base.registered_gas_limit,
            request.apply_blacklist,
            request.inclusion_list,
        )
        .await
    }

    /// Core logic for appending additional transactions to a block.
    async fn merge_block_v1(
        &self,
        request: MergeBlockRequestV1,
    ) -> Result<MergeBlockResponseV1, ValidationApiError> {
        info!(target: "rpc::relay", "Merging block v1");

        let block: alloy_consensus::Block<
            <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx,
        > = request
            .execution_payload
            .try_into_block()
            .map_err(|e| NewPayloadError::Eth(e))?;

        // Leave some gas for the final revenue distribution call
        // and the proposer payment.
        // The gas cost should be 10k per target, but could jump
        // to 35k if the targets are new accounts.
        // This number leaves us space for ~9 non-empty targets, or ~2 new accounts.
        // TODO: compute dynamically by keeping track of gas cost
        let max_distribution_gas = 100000;
        // We also leave some gas for the final proposer payment
        let gas_limit = block.gas_limit() - max_distribution_gas - 21000;

        let latest_header = self
            .provider
            .latest_header()?
            .ok_or_else(|| ValidationApiError::MissingLatestBlock)?;

        let parent_header = if block.parent_hash() == latest_header.hash() {
            latest_header
        } else {
            // parent is not the latest header so we need to fetch it and ensure it's not too old
            let parent_header = self
                .provider
                .sealed_header_by_hash(block.parent_hash())?
                .ok_or_else(|| ValidationApiError::MissingParentBlock)?;

            if latest_header
                .number()
                .saturating_sub(parent_header.number())
                > self.validation_window
            {
                return Err(ValidationApiError::BlockTooOld);
            }
            parent_header
        };

        let (header, body) = block.split();

        let (withdrawals, mut transactions) = (body.withdrawals, body.transactions);

        let block_base_fee_per_gas = header.base_fee_per_gas().unwrap_or_default();

        let proposer_fee_recipient = request.proposer_fee_recipient;
        let relay_fee_recipient = self.relay_fee_recipient;
        let beneficiary = header.beneficiary();

        let new_block_attrs = NextBlockEnvAttributes {
            timestamp: header.timestamp(),
            suggested_fee_recipient: beneficiary,
            prev_randao: header.difficulty().to_be_bytes().into(),
            gas_limit: header.gas_limit(),
            parent_beacon_block_root: header.parent_beacon_block_root(),
            withdrawals,
        };

        let parent_hash = header.parent_hash();

        let state_provider = self.provider.state_by_block_hash(parent_hash)?;

        let mut request_cache = self.cached_reads(parent_hash).await;

        let cached_db = request_cache.as_db(StateProviderDatabase::new(&state_provider));

        let mut state_db = State::builder().with_database_ref(&cached_db).build();
        // Execute the base block
        let evm_env = self
            .evm_config
            .next_evm_env(&parent_header, &new_block_attrs)
            .or(Err(ValidationApiError::NextEvmEnvFail))?;

        let evm = self.evm_config.evm_with_env(&mut state_db, evm_env.clone());
        let ctx = self
            .evm_config
            .context_for_next_block(&parent_header, new_block_attrs.clone());
        let mut block_executor = self.evm_config.create_executor(evm, ctx);

        block_executor.apply_pre_execution_changes()?;

        let mut gas_used = 0;

        let mut all_transactions: Vec<
            Recovered<<<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx>,
        > = Vec::with_capacity(transactions.len());

        // Check that block has proposer payment, otherwise reject it
        let Some(tx) = transactions.last() else {
            return Err(ValidationApiError::ProposerPayment);
        };
        if tx.value() != request.value || tx.to() != Some(proposer_fee_recipient) {
            // TODO: check what to do here
            return Err(ValidationApiError::ProposerPayment);
        }
        // Remove proposer payment, we'll later add our own payment
        transactions.pop();

        // Insert the transactions from the unmerged block
        for tx in transactions {
            let tx = tx.try_into_recovered().expect("signature is valid");
            gas_used += block_executor.execute_transaction(tx.as_executable())?;

            all_transactions.push(tx.clone());
        }

        let initial_balance = block_executor
            .evm_mut()
            .db_mut()
            .basic(beneficiary)?
            .map_or(U256::ZERO, |info| info.balance);

        let mut revenues = HashMap::new();

        let mut current_balance = initial_balance;

        // Append transactions until we run out of space
        for (origin, bundle) in request
            .merging_data
            .into_iter()
            .flat_map(|mb| mb.bundles.into_iter().map(move |b| (mb.origin, b)))
        {
            // Clone current state to avoid mutating it
            // TODO: there should be a way to remove this clone
            let mut db_clone = {
                let db = block_executor.evm_mut().db_mut();
                db.merge_transitions(BundleRetention::Reverts);

                let pre_state = db.bundle_state.clone();

                State::builder()
                    .with_database_ref(&cached_db)
                    .with_bundle_prestate(pre_state)
                    .build()
            };
            // Create a new EVM with the cloned pre-state
            let mut evm_clone = self.evm_config.evm_with_env(&mut db_clone, evm_env.clone());

            let Ok(txs): Result<Vec<Recovered<<<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx>>, _> = bundle.transactions.into_iter().map(|b|{
                let mut buf = b.as_ref();
                let tx = <<<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx as Decodable2718>::decode_2718(&mut buf)?;
                if !buf.is_empty() {
                    return Err(alloy_rlp::Error::UnexpectedLength);
                }
                let recovered = tx.try_into_recovered().or(Err(alloy_rlp::Error::Custom("invalid signature")))?;
                Ok(recovered)
            }).collect() else {
                // The mergeable transactions should come from already validated payloads
                // But in case decoding fails, we just skip the bundle
                continue;
            };

            let mut gas_used_in_bundle = 0;
            let mut bundle_is_valid = true;
            let mut should_be_included = vec![true; txs.len()];

            // Check the bundle can be included in the block
            for (i, tx) in txs.iter().enumerate() {
                // TODO: handle blob transactions
                if tx.blob_count().unwrap_or(0) != 0 {
                    bundle_is_valid = false;
                    break;
                }
                match evm_clone.transact(tx) {
                    Ok(result) => {
                        // If tx reverted and is not allowed to
                        if !result.result.is_success() && !bundle.reverting_txs.contains(&i) {
                            // We check if we can drop it instead, else we discard this bundle
                            if bundle.dropping_txs.contains(&i) {
                                // Tx should be dropped
                                should_be_included[i] = false;
                            } else {
                                bundle_is_valid = false;
                                break;
                            }
                        }
                        gas_used_in_bundle += result.result.gas_used();
                        // Apply the state changes to the cloned state
                        // Note that this only commits to the State object, not the database
                        evm_clone.db_mut().commit(result.state);
                    }
                    Err(e) => {
                        if e.is_invalid_tx_err() && bundle.dropping_txs.contains(&i) {
                            // The transaction might have been invalidated by another one, so we drop it
                            should_be_included[i] = false;
                        } else {
                            // The error isn't transaction-related, so we just try to skip this bundle
                            bundle_is_valid = false;
                            break;
                        }
                    }
                };
            }
            if !bundle_is_valid || gas_used + gas_used_in_bundle > gas_limit {
                continue;
            }

            // Execute the transaction bundle

            let mut total_value = U256::ZERO;

            for (i, tx) in txs.into_iter().enumerate() {
                if !should_be_included[i] {
                    continue;
                }
                gas_used += block_executor.execute_transaction(tx.as_executable())?;

                all_transactions.push(tx.clone());
            }
            // Consider any balance changes on the beneficiary as tx value
            let new_balance = block_executor
                .evm_mut()
                .db_mut()
                .basic(beneficiary)?
                .map_or(U256::ZERO, |info| info.balance);

            total_value += new_balance.saturating_sub(current_balance);
            current_balance = new_balance;

            // Update the revenue for the bundle's origin
            if !total_value.is_zero() {
                revenues
                    .entry(origin)
                    .and_modify(|v| *v += total_value)
                    .or_insert(total_value);
            }
        }

        let mut updated_revenues = HashMap::with_capacity(revenues.len());

        let mut distributed_value = U256::ZERO;

        // We divide the revenue among the winning builder, proposer, flow origin, and the relay.
        // We assume the winning builder controls the beneficiary address, and so it will receive any undistributed revenue.
        for (origin, revenue) in revenues {
            let relay_revenue = revenue / U256::from(4);
            updated_revenues
                .entry(relay_fee_recipient)
                .and_modify(|v| *v += relay_revenue)
                .or_insert(relay_revenue);

            let proposer_revenue = revenue / U256::from(4);
            updated_revenues
                .entry(proposer_fee_recipient)
                .and_modify(|v| *v += proposer_revenue)
                .or_insert(proposer_revenue);

            let builder_revenue = revenue / U256::from(4);
            updated_revenues
                .entry(origin)
                .and_modify(|v| *v += builder_revenue)
                .or_insert(builder_revenue);

            distributed_value += builder_revenue + relay_revenue + proposer_revenue;
        }

        // Just in case, we remove the beneficiary address from the distribution
        updated_revenues.remove(&beneficiary);

        // We also remove the proposer revenue, to pay it in a direct transaction
        let proposer_added_value = updated_revenues
            .remove(&proposer_fee_recipient)
            .unwrap_or(U256::ZERO);
        let proposer_value = request.value + proposer_added_value;

        let updated_revenues: Vec<_> = updated_revenues.into_iter().collect();

        let calldata = encode_disperse_eth_calldata(&updated_revenues);

        // Get the chain ID from any transaction in the block, defaulting to 1 (mainnet) if none was found
        // TODO: check if this is OK
        let chain_id = all_transactions
            .iter()
            .find_map(|tx| tx.chain_id())
            .unwrap_or(1);

        let nonce = block_executor
            .evm_mut()
            .db_mut()
            .basic(beneficiary)?
            .map_or(0, |info| info.nonce)
            + 1;

        let disperse_tx = TxEip1559 {
            chain_id,
            nonce,
            // TODO: compute proper gas limit
            gas_limit: max_distribution_gas,
            max_fee_per_gas: block_base_fee_per_gas.into(),
            max_priority_fee_per_gas: 0,
            to: self.distribution_contract.into(),
            value: distributed_value,
            access_list: Default::default(),
            input: calldata.into(),
        };

        // Sign the transaction
        let signature = self
            .merger_signer
            .sign_hash_sync(&disperse_tx.signature_hash())
            .expect("signer is local and private key is valid");
        let signed_disperse_tx = disperse_tx.into_signed(signature);

        // We encode and decode the transaction to turn it into the same SignedTx type expected by the type bounds
        let mut buf = vec![];
        signed_disperse_tx.encode_2718(&mut buf);
        let signed_tx = <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx::decode_2718(
            &mut buf.as_slice(),
        )
        .expect("we just encoded it with encode_2718");
        let recovered_signed_disperse_tx =
            Recovered::new_unchecked(signed_tx, self.merger_signer.address());

        all_transactions.push(recovered_signed_disperse_tx);

        drop(block_executor);

        // Add proposer payment tx
        let proposer_payment_tx = TxEip1559 {
            chain_id,
            nonce: nonce + 1,
            // Note that this will revert on any smart contract target
            gas_limit: 21000,
            max_fee_per_gas: block_base_fee_per_gas.into(),
            max_priority_fee_per_gas: 0,
            to: proposer_fee_recipient.into(),
            value: proposer_value,
            access_list: Default::default(),
            input: Default::default(),
        };

        // Sign the transaction
        let signature = self
            .merger_signer
            .sign_hash_sync(&proposer_payment_tx.signature_hash())
            .expect("signer is local and private key is valid");
        let signed_proposer_payment_tx = proposer_payment_tx.into_signed(signature);

        // We encode and decode the transaction to turn it into the same SignedTx type expected by the type bounds
        let mut buf = vec![];
        signed_proposer_payment_tx.encode_2718(&mut buf);
        let signed_tx = <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx::decode_2718(
            &mut buf.as_slice(),
        )
        .expect("we just encoded it with encode_2718");
        let recovered_signed_proposer_payment_tx =
            Recovered::new_unchecked(signed_tx, self.merger_signer.address());

        all_transactions.push(recovered_signed_proposer_payment_tx);

        let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));

        let mut state_db = State::builder().with_database(cached_db).build();
        let mut builder = self
            .evm_config
            .builder_for_next_block(&mut state_db, &parent_header, new_block_attrs)
            .or(Err(ValidationApiError::NextBuilderFail))?;

        // We re-execute all transactions due to limitations on the BlockBuilder API
        // TODO: check if we can avoid this
        for tx in all_transactions {
            builder.execute_transaction(tx)?;
        }

        let outcome = builder.finish(&state_provider)?;

        let blob_gas_used = outcome.block.blob_gas_used().unwrap_or(0);
        let excess_blob_gas = outcome.block.excess_blob_gas().unwrap_or(0);
        let block = outcome.block.into_block().into_ethereum_block();

        let payload_inner = ExecutionPayloadV2::from_block_slow(&block);
        let execution_payload = ExecutionPayloadV3 {
            payload_inner,
            blob_gas_used,
            excess_blob_gas,
        };
        let execution_requests = outcome
            .execution_result
            .requests
            .try_into()
            .or(Err(ValidationApiError::ExecutionRequests))?;
        // We assume that no new blobs were added to the block
        // TODO: support blob transactions?
        let blobs_bundle = request.blobs_bundle;

        let response = MergeBlockResponseV1 {
            execution_payload,
            execution_requests,
            blobs_bundle,
            value: proposer_value,
        };

        Ok(response)
    }
}

#[async_trait]
impl<Provider, E> BlockSubmissionValidationApiServer for ValidationApi<Provider, E>
where
    Provider: BlockReaderIdExt<Header = <E::Primitives as NodePrimitives>::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + StateProviderFactory
        + Clone
        + 'static,
    E: ConfigureEvm + 'static,
{
    async fn validate_builder_submission_v1(
        &self,
        _request: BuilderBlockValidationRequest,
    ) -> RpcResult<()> {
        warn!(target: "rpc::relay", "Method `relay_validateBuilderSubmissionV1` is not supported");
        Err(internal_rpc_err("unimplemented"))
    }

    async fn validate_builder_submission_v2(
        &self,
        _request: BuilderBlockValidationRequestV2,
    ) -> RpcResult<()> {
        warn!(target: "rpc::relay", "Method `relay_validateBuilderSubmissionV2` is not supported");
        Err(internal_rpc_err("unimplemented"))
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking(Box::pin(async move {
            let result = Self::validate_builder_submission_v3(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        }));

        rx.await
            .map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v4(
        &self,
        request: ExtendedValidationRequestV4,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking(Box::pin(async move {
            let result = Self::validate_builder_submission_v4(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        }));

        rx.await
            .map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }

    /// A Request to append mergeable transactions to a block.
    async fn merge_block_v1(
        &self,
        request: MergeBlockRequestV1,
    ) -> jsonrpsee::core::RpcResult<MergeBlockResponseV1> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking(Box::pin(async move {
            let result = Self::merge_block_v1(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        }));

        rx.await
            .map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }
}

pub struct ValidationApiInner<Provider, E: ConfigureEvm> {
    /// The provider that can interact with the chain.
    provider: Provider,
    /// Consensus implementation.
    consensus: Arc<dyn FullConsensus<E::Primitives, Error = ConsensusError>>,
    /// Execution payload validator.
    payload_validator: Arc<
        dyn PayloadValidator<
                Block = <E::Primitives as NodePrimitives>::Block,
                ExecutionData = ExecutionData,
            >,
    >,
    /// Block executor factory.
    evm_config: E,
    /// Set of disallowed addresses
    disallow: Arc<DashSet<Address>>,
    /// The maximum block distance - parent to latest - allowed for validation
    validation_window: u64,
    /// Cached state reads to avoid redundant disk I/O across multiple validation attempts
    /// targeting the same state. Stores a tuple of (`block_hash`, `cached_reads`) for the
    /// latest head block state. Uses async `RwLock` to safely handle concurrent validation
    /// requests.
    cached_state: RwLock<(B256, CachedReads)>,
    /// Task spawner for blocking operations
    task_spawner: Box<dyn TaskSpawner>,
    /// Validation metrics
    metrics: ValidationMetrics,
    /// The address to send relay revenue to.
    relay_fee_recipient: Address,
    /// The signer to use for merging blocks. It will be used for signing the
    /// revenue distribution and proposer payment transactions.
    merger_signer: PrivateKeySigner,
    /// The address of the contract used to distribute rewards.
    /// It must have a `disperseEther(address[],uint256[])` function.
    distribution_contract: Address,
}

impl<Provider, E: ConfigureEvm> fmt::Debug for ValidationApiInner<Provider, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationApiInner").finish_non_exhaustive()
    }
}

/// Configuration for validation API.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidationApiConfig {
    /// Blacklist endpoint.
    pub blacklist_endpoint: String,
    /// The maximum block distance - parent to latest - allowed for validation
    pub validation_window: u64,
    /// Private key to use for merging blocks.
    /// The address of this key will be used as the beneficiary for merged blocks,
    /// and it will be used for signing the revenue distribution transaction.
    pub merger_private_key: String,
    /// The address to send relay revenue to.
    pub relay_fee_recipient: String,
}

impl ValidationApiConfig {
    /// Default validation blocks window of 3 blocks
    pub const DEFAULT_VALIDATION_WINDOW: u64 = 3;

    pub fn new(
        blacklist_endpoint: String,
        merger_private_key: String,
        relay_fee_recipient: String,
    ) -> Self {
        Self {
            blacklist_endpoint,
            validation_window: Self::DEFAULT_VALIDATION_WINDOW,
            merger_private_key,
            relay_fee_recipient,
        }
    }
}

impl Default for ValidationApiConfig {
    fn default() -> Self {
        Self {
            blacklist_endpoint: Default::default(),
            validation_window: Self::DEFAULT_VALIDATION_WINDOW,
            merger_private_key: String::from("0x00"),
            relay_fee_recipient: String::from("0x00"),
        }
    }
}

/// Errors thrown by the validation API.
#[derive(Debug, thiserror::Error)]
pub enum ValidationApiError {
    #[error("block gas limit mismatch: {_0}")]
    GasLimitMismatch(GotExpected<u64>),
    #[error("block gas used mismatch: {_0}")]
    GasUsedMismatch(GotExpected<u64>),
    #[error("block parent hash mismatch: {_0}")]
    ParentHashMismatch(GotExpected<B256>),
    #[error("block hash mismatch: {_0}")]
    BlockHashMismatch(GotExpected<B256>),
    #[error("missing latest block in database")]
    MissingLatestBlock,
    #[error("parent block not found")]
    MissingParentBlock,
    #[error("block is too old, outside validation window")]
    BlockTooOld,
    #[error("could not verify proposer payment")]
    ProposerPayment,
    #[error("invalid blobs bundle")]
    InvalidBlobsBundle,
    #[error("block accesses blacklisted address: {_0}")]
    Blacklist(Address),
    #[error(transparent)]
    Blob(#[from] BlobTransactionValidationError),
    #[error(transparent)]
    Consensus(#[from] ConsensusError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Execution(#[from] BlockExecutionError),
    #[error(transparent)]
    Payload(#[from] NewPayloadError),
    #[error("inclusion list not statisfied")]
    InclusionList,
    #[error("failed to create EvmEnv for next block")]
    NextEvmEnvFail,
    #[error("failed to create builder for next block")]
    NextBuilderFail,
    #[error("failed to decode execution requests")]
    ExecutionRequests,
}

impl From<ValidationApiError> for ErrorObject<'static> {
    fn from(error: ValidationApiError) -> Self {
        match error {
            ValidationApiError::GasLimitMismatch(_)
            | ValidationApiError::GasUsedMismatch(_)
            | ValidationApiError::ParentHashMismatch(_)
            | ValidationApiError::BlockHashMismatch(_)
            | ValidationApiError::Blacklist(_)
            | ValidationApiError::ProposerPayment
            | ValidationApiError::InvalidBlobsBundle
            | ValidationApiError::InclusionList
            | ValidationApiError::ExecutionRequests
            | ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

            ValidationApiError::MissingLatestBlock
            | ValidationApiError::MissingParentBlock
            | ValidationApiError::BlockTooOld
            | ValidationApiError::NextEvmEnvFail
            | ValidationApiError::NextBuilderFail
            | ValidationApiError::Consensus(_)
            | ValidationApiError::Provider(_) => internal_rpc_err(error.to_string()),
            ValidationApiError::Execution(err) => match err {
                error @ BlockExecutionError::Validation(_) => {
                    invalid_params_rpc_err(error.to_string())
                }
                error @ BlockExecutionError::Internal(_) => internal_rpc_err(error.to_string()),
            },
            ValidationApiError::Payload(err) => match err {
                error @ NewPayloadError::Eth(_) => invalid_params_rpc_err(error.to_string()),
                error @ NewPayloadError::Other(_) => internal_rpc_err(error.to_string()),
            },
        }
    }
}

/// Metrics for the validation endpoint.
#[derive(Metrics)]
#[metrics(scope = "builder.validation")]
pub(crate) struct ValidationMetrics {
    /// The number of entries configured in the builder validation disallow list.
    pub(crate) disallow_size: Gauge,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InclusionList {
    pub txs: Vec<InclusionListTx>,
}

impl InclusionList {
    pub const fn empty() -> Self {
        Self { txs: vec![] }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InclusionListTx {
    pub hash: B256,
    pub nonce: u64,
    pub sender: Address,
    pub gas_priority_fee: u64,
    pub bytes: Bytes,
    pub wait_time: u32,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedValidationRequestV4 {
    #[serde(flatten)]
    pub base: BuilderBlockValidationRequestV4,

    pub inclusion_list: Option<InclusionList>,

    #[serde(default)]
    pub apply_blacklist: bool,
}

/// Represents one or more transactions to be appended into a block atomically.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeableBundle {
    /// List of transactions that can be merged into the block.
    pub transactions: Vec<Bytes>,
    /// Txs that may revert.
    pub reverting_txs: Vec<usize>,
    /// Txs that are allowed to be omitted, but not revert.
    pub dropping_txs: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeableBundles {
    /// Address of the builder that submitted these bundles.
    pub origin: Address,
    /// List of mergeable bundles.
    pub bundles: Vec<MergeableBundle>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBlockRequestV1 {
    /// The original payload value
    pub value: U256,
    /// The address to send the proposer payment to.
    pub proposer_fee_recipient: Address,
    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
    pub execution_payload: ExecutionPayloadV3,
    pub blobs_bundle: BlobsBundleV1,
    pub merging_data: Vec<MergeableBundles>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBlockResponseV1 {
    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
    pub execution_payload: ExecutionPayloadV3,
    pub execution_requests: ExecutionRequestsV4,
    pub blobs_bundle: BlobsBundleV1,
    /// Total value for the proposer
    pub value: U256,
}

/// Block validation rpc interface.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "relay"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "relay"))]
pub trait BlockSubmissionValidationApi {
    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV1")]
    async fn validate_builder_submission_v1(
        &self,
        request: BuilderBlockValidationRequest,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV2")]
    async fn validate_builder_submission_v2(
        &self,
        request: BuilderBlockValidationRequestV2,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV3")]
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV4")]
    async fn validate_builder_submission_v4(
        &self,
        request: ExtendedValidationRequestV4,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to append mergeable transactions to a block.
    #[method(name = "mergeBlockV1")]
    async fn merge_block_v1(
        &self,
        request: MergeBlockRequestV1,
    ) -> jsonrpsee::core::RpcResult<MergeBlockResponseV1>;
}

/// Encodes a call to `disperseEther(address[],uint256[])` with the given recipients and values.
fn encode_disperse_eth_calldata(input: &[(Address, U256)]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 64 + input.len() * 32 * 2);
    // selector for "disperseEther(address[],uint256[])"
    calldata.extend_from_slice(&[0xe6, 0x3d, 0x38, 0xed]);
    // Offset for recipients from start of calldata (without counting selector)
    // 32 bytes for each offset = 64
    let recipients_offset: [u8; 32] = U256::from(64).to_be_bytes();
    calldata.extend_from_slice(&recipients_offset);
    // Offset for values from start of calldata (without counting selector)
    // 32 bytes for each offset + 32 bytes for recipients length + 32 bytes for each recipient
    let values_offset: [u8; 32] = (U256::from(64 + 32 + input.len() * 32)).to_be_bytes();
    calldata.extend_from_slice(&values_offset);

    let revenues_length: [u8; 32] = U256::from(input.len()).to_be_bytes();
    calldata.extend_from_slice(&revenues_length);

    calldata.extend(input.iter().flat_map(|(recipient, _)| {
        let mut arr = [0_u8; 32];
        arr[12..].copy_from_slice(recipient.as_slice());
        arr
    }));

    calldata.extend_from_slice(&revenues_length);

    calldata.extend(
        input
            .iter()
            .flat_map(|(_, value)| value.to_be_bytes::<32>()),
    );
    calldata
}

#[cfg(test)]
mod tests {
    use revm_primitives::hex;

    use super::*;

    #[test]
    fn test_disperse_calldata_encoding() {
        let expected = hex!(
            // Selector
            "e63d38ed"
            // Recipients offset
            "0000000000000000000000000000000000000000000000000000000000000040"
            // Values offset
            "00000000000000000000000000000000000000000000000000000000000000c0"
            // Recipients length
            "0000000000000000000000000000000000000000000000000000000000000003"
            // Recipients (padded to 32 bytes)
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000003"
            // Values length
            "0000000000000000000000000000000000000000000000000000000000000003"
            // Values
            "0000000000000000000000000000000000000000000000000000000000000005"
            "0000000000000000000000000000000000000000000000000000000000000006"
            "0000000000000000000000000000000000000000000000000000000000000007"
        );
        let input = [
            (Address::left_padding_from(&[1]), U256::from(5)),
            (Address::left_padding_from(&[2]), U256::from(6)),
            (Address::left_padding_from(&[3]), U256::from(7)),
        ];
        let actual = encode_disperse_eth_calldata(&input);
        assert_eq!(actual, expected);
    }
}
