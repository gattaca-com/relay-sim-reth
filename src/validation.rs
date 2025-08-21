use alloy_consensus::proofs::ordered_trie_root_with_encoder;
use alloy_consensus::{
    BlobTransactionValidationError, Block, BlockBody, BlockHeader, EMPTY_OMMER_ROOT_HASH,
    EnvKzgSettings, Header, SignableTransaction, Transaction, TxEip1559, TxReceipt,
};
use alloy_eips::eip4895::Withdrawals;
use alloy_eips::eip7685::Requests;
use alloy_eips::merge::BEACON_NONCE;
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
use reth_ethereum::chainspec::EthChainSpec;
use reth_ethereum::evm::primitives::block::{BlockExecutor, BlockExecutorFor};
use reth_ethereum::evm::primitives::execute::ExecutorTx;
use reth_ethereum::evm::primitives::{EvmEnvFor, EvmError};
use reth_ethereum::primitives::proofs;
use reth_ethereum::storage::StateProvider;
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
    Block as _, BlockBody as _, ConfigureEvm, NewPayloadError, NextBlockEnvAttributes,
    NodePrimitives, PayloadValidator,
};
use reth_primitives::{Recovered, SealedHeader, logs_bloom};
use reth_tasks::TaskSpawner;
use revm::database::CacheDB;
use revm::database::states::bundle_state::BundleRetention;
use revm::{Database, database::State};
use revm::{DatabaseCommit, DatabaseRef};
use revm_primitives::{Address, B256, U256, address};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{BinaryHeap, HashMap};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{
    spawn,
    sync::{RwLock, oneshot},
    time,
};
use tracing::{info, warn};

type SignedTx<E> = <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx;
type RecoveredBlockFor<E> = RecoveredBlock<Block<SignedTx<E>>>;
type RecoveredTx<E> = Recovered<SignedTx<E>>;

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
            distribution_config,
            distribution_contract,
            validate_merged_blocks,
        } = config;
        let disallow = Arc::new(DashSet::new());

        let merger_signer = merger_private_key
            .parse()
            .expect("Failed to parse merger private key");

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
            distribution_config,
            distribution_contract,
            validate_merged_blocks,
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

        let parent_header = self.get_parent_header(block.parent_hash())?;

        self.consensus
            .validate_header_against_parent(block.sealed_header(), &parent_header)?;
        let parent_header_hash = parent_header.hash();
        let state_provider = self.provider.state_by_block_hash(parent_header_hash)?;

        let mut request_cache = self.cached_reads(parent_header_hash).await;

        let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));

        let mut executor = self.evm_config.batch_executor(cached_db);

        let mut accessed_blacklisted = None;

        let result = executor.execute_one(&block)?;

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
        DB: Database + core::fmt::Debug,
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
            let bytes_slice = req.bytes.as_ref();
            let transaction = recover_raw_transaction(bytes_slice)
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
            Err(ValidationApiError::GasUsedMismatch(GotExpected {
                got: message.gas_used,
                expected: header.gas_used(),
            }))
        } else {
            Ok(())
        }
    }

    /// Ensures that the chosen gas limit is the closest possible value for the validator's
    /// registered gas limit.
    ///
    /// Ref: <https://github.com/flashbots/builder/blob/a742641e24df68bc2fc476199b012b0abce40ffe/core/blockchain.go#L2474-L2477>
    fn _validate_gas_limit(
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

        let block: alloy_consensus::Block<SignedTx<E>> = request
            .execution_payload
            .try_into_block()
            .map_err(NewPayloadError::Eth)?;

        let (header, body) = block.split();

        let (withdrawals, mut transactions) = (body.withdrawals, body.transactions);

        let block_base_fee_per_gas = header.base_fee_per_gas().unwrap_or_default();

        let proposer_fee_recipient = request.proposer_fee_recipient;
        let relay_fee_recipient = self.relay_fee_recipient;
        let beneficiary = header.beneficiary();

        // Check that block has proposer payment, otherwise reject it.
        // Also remove proposer payment, we'll later add our own
        let Some(payment_tx) = transactions.pop() else {
            return Err(ValidationApiError::MissingProposerPayment);
        };
        if payment_tx.value() != request.original_value
            || payment_tx.to() != Some(proposer_fee_recipient)
        {
            return Err(ValidationApiError::ProposerPayment);
        }

        // Leave some gas for the final revenue distribution call
        // and the proposer payment.
        // The gas cost should be 10k per target, but could jump
        // to 35k if the targets are new accounts.
        // This number leaves us space for ~9 non-empty targets, or ~2 new accounts.
        // TODO: compute dynamically by keeping track of gas cost
        let max_distribution_gas = 100000;
        // We also leave some gas for the final proposer payment
        let gas_limit = header.gas_limit() - max_distribution_gas - payment_tx.gas_limit();

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

        let parent_header = self.get_parent_header(parent_hash)?;

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

        let mut all_transactions: Vec<RecoveredTx<E>> = Vec::with_capacity(transactions.len());

        // Keep track of appended orders with blobs
        let mut appended_blob_order_indices = vec![];
        let mut blob_versioned_hashes = vec![];

        // Insert the transactions from the unmerged block
        for tx in transactions {
            let tx = tx.try_into_recovered().expect("signature is valid");
            gas_used += block_executor.execute_transaction(tx.as_executable())?;

            all_transactions.push(tx.clone());
            if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                blob_versioned_hashes.extend(versioned_hashes);
            }
        }

        // We use a read-only reference to the State<DB> as a Database.
        // When simulating, we're going to wrap this with an in-memory DB.
        let end_of_block_state = &**block_executor.evm_mut().db_mut();

        let initial_balance = end_of_block_state
            .basic_ref(beneficiary)?
            .map_or(U256::ZERO, |info| info.balance);

        // Keep a list of valid transactions and an index by score
        let mut mergeable_transactions = Vec::with_capacity(request.merging_data.len());
        let mut txs_by_score = BinaryHeap::with_capacity(mergeable_transactions.len());

        // Simulate orders, ordering them by expected value, discarding invalid ones
        for (original_index, (origin, order)) in request
            .merging_data
            .iter()
            .map(|mb| (mb.origin, &mb.order))
            .enumerate()
        {
            let Ok(txs) = recover_transactions::<E>(order) else {
                // The mergeable transactions should come from already validated payloads
                // But in case decoding fails, we just skip the bundle
                continue;
            };

            let db = block_executor.evm_mut().db_mut();
            let reverting_txs = order.reverting_txs();
            let dropping_txs = order.dropping_txs();

            let (bundle_is_valid, gas_used_in_bundle, _, cached_db) =
                self.simulate_bundle(db, evm_env.clone(), reverting_txs, dropping_txs, &txs);

            if !bundle_is_valid || gas_used + gas_used_in_bundle > gas_limit {
                continue;
            }

            // Consider any balance changes on the beneficiary as tx value
            let new_balance = cached_db
                .basic_ref(beneficiary)?
                .map_or(U256::ZERO, |info| info.balance);

            let total_value = new_balance.saturating_sub(initial_balance);

            // Keep the bundle for further processing
            if !total_value.is_zero() {
                let index = mergeable_transactions.len();
                // Use the tx's value as its score
                // We could use other heuristics here
                let score = total_value;
                txs_by_score.push((score, index));
                mergeable_transactions.push((origin, original_index, txs));
            }
        }

        let mut revenues = HashMap::new();

        let mut current_balance = initial_balance;

        // Append transactions by score until we run out of space
        while let Some((_score, i)) = txs_by_score.pop() {
            let (origin, original_index, txs) = std::mem::take(&mut mergeable_transactions[i]);
            let order = &request.merging_data[original_index].order;

            let db = block_executor.evm_mut().db_mut();
            let reverting_txs = order.reverting_txs();
            let dropping_txs = order.dropping_txs();

            let (bundle_is_valid, gas_used_in_bundle, should_be_included, _) =
                self.simulate_bundle(db, evm_env.clone(), reverting_txs, dropping_txs, &txs);

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
                // If tx has blobs, store the order index and tx sub-index to add the blobs to the payload
                // Also store the versioned hash for validation
                if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                    appended_blob_order_indices.push((original_index, i));
                    blob_versioned_hashes.extend(versioned_hashes);
                }
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
        drop(mergeable_transactions);

        let (distributed_value, mut updated_revenues) = split_revenue(
            &self.distribution_config,
            revenues,
            relay_fee_recipient,
            proposer_fee_recipient,
        );

        // Just in case, we remove the beneficiary address from the distribution
        updated_revenues.remove(&beneficiary);

        // We also remove the proposer revenue, to pay it in a direct transaction
        let proposer_added_value = updated_revenues
            .remove(&proposer_fee_recipient)
            .unwrap_or(U256::ZERO);
        let proposer_value = request.original_value + proposer_added_value;

        let calldata = encode_disperse_eth_calldata(&updated_revenues);

        // Get the chain ID from the configured provider
        let chain_id = self.provider.chain_spec().chain_id();

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

        let signed_disperse_tx_arr = [self.sign_transaction(disperse_tx)?];

        let db = block_executor.evm_mut().db_mut();
        let (is_valid, _, _, _) =
            self.simulate_bundle(db, evm_env.clone(), &[], &[], &signed_disperse_tx_arr);
        if !is_valid {
            return Err(ValidationApiError::RevenueAllocationReverted);
        }

        let [signed_disperse_tx] = signed_disperse_tx_arr;
        all_transactions.push(signed_disperse_tx);

        // Add proposer payment tx
        let proposer_payment_tx = TxEip1559 {
            chain_id,
            nonce: nonce + 1,
            gas_limit: payment_tx.gas_limit(),
            max_fee_per_gas: block_base_fee_per_gas.into(),
            max_priority_fee_per_gas: 0,
            to: proposer_fee_recipient.into(),
            value: proposer_value,
            access_list: Default::default(),
            input: Default::default(),
        };

        let signed_proposer_payment_tx_arr = [self.sign_transaction(proposer_payment_tx)?];

        let db = block_executor.evm_mut().db_mut();
        let (is_valid, _, _, _) = self.simulate_bundle(
            db,
            evm_env.clone(),
            &[],
            &[],
            &signed_proposer_payment_tx_arr,
        );
        if !is_valid {
            return Err(ValidationApiError::RevenueAllocationReverted);
        }

        let [signed_proposer_payment_tx] = signed_proposer_payment_tx_arr;

        all_transactions.push(signed_proposer_payment_tx);

        let (new_block, requests) = self.assemble_block(
            block_executor,
            &state_provider,
            all_transactions,
            new_block_attrs.withdrawals,
            parent_header,
            header,
        )?;

        let blob_gas_used = new_block.blob_gas_used().unwrap_or(0);
        let excess_blob_gas = new_block.excess_blob_gas().unwrap_or(0);
        let block = new_block.into_block().into_ethereum_block();

        let payload_inner = ExecutionPayloadV2::from_block_slow(&block);

        let block_hash = payload_inner.payload_inner.block_hash;

        let execution_payload = ExecutionPayloadV3 {
            payload_inner,
            blob_gas_used,
            excess_blob_gas,
        };
        let execution_requests: ExecutionRequestsV4 = requests
            .try_into()
            .or(Err(ValidationApiError::ExecutionRequests))?;

        if self.validate_merged_blocks {
            let gas_used = execution_payload.payload_inner.payload_inner.gas_used;
            let message = BidTrace {
                slot: 0, // unused
                parent_hash,
                block_hash,
                builder_pubkey: Default::default(),  // unused
                proposer_pubkey: Default::default(), // unused
                proposer_fee_recipient,
                gas_limit: new_block_attrs.gas_limit,
                gas_used,
                value: proposer_value,
            };
            let block = self
                .payload_validator
                .ensure_well_formed_payload(ExecutionData {
                    payload: ExecutionPayload::V3(execution_payload.clone()),
                    sidecar: ExecutionPayloadSidecar::v4(
                        CancunPayloadFields {
                            parent_beacon_block_root: new_block_attrs
                                .parent_beacon_block_root
                                .unwrap(),
                            versioned_hashes: blob_versioned_hashes,
                        },
                        PraguePayloadFields {
                            requests: RequestsOrHash::Requests(execution_requests.to_requests()),
                        },
                    ),
                })?;

            self.validate_message_against_block(block, message, 0, false, None)
                .await?;
        }

        let response = MergeBlockResponseV1 {
            execution_payload,
            execution_requests,
            appended_blob_order_indices,
            proposer_value,
        };

        Ok(response)
    }

    /// Simulates a bundle.
    /// Returns whether the bundle is valid, the amount of gas used, and a list
    /// marking whether to include a transaction or not.
    fn simulate_bundle<DBRef>(
        &self,
        db_ref: DBRef,
        evm_env: EvmEnvFor<E>,
        reverting_txs: &[usize],
        dropping_txs: &[usize],
        txs: &[RecoveredTx<E>],
    ) -> (bool, u64, Vec<bool>, CacheDB<DBRef>)
    where
        DBRef: DatabaseRef + core::fmt::Debug,
        DBRef::Error: Send + Sync + 'static,
    {
        // Clone current state to avoid mutating it
        let cached_db = CacheDB::new(db_ref);
        // Create a new EVM with the cloned pre-state
        let mut evm = self.evm_config.evm_with_env(cached_db, evm_env.clone());

        let mut gas_used_in_bundle = 0;
        let mut included_txs = vec![true; txs.len()];

        // Check the bundle can be included in the block
        for (i, tx) in txs.iter().enumerate() {
            match evm.transact(tx) {
                Ok(result) => {
                    // If tx reverted and is not allowed to
                    if !result.result.is_success() && !reverting_txs.contains(&i) {
                        // We check if we can drop it instead, else we discard this bundle
                        if dropping_txs.contains(&i) {
                            // Tx should be dropped
                            included_txs[i] = false;
                        } else {
                            return (false, 0, vec![], evm.into_db());
                        }
                    }
                    gas_used_in_bundle += result.result.gas_used();
                    // Apply the state changes to the cloned state
                    // Note that this only commits to the State object, not the database
                    evm.db_mut().commit(result.state);
                }
                Err(e) => {
                    if e.is_invalid_tx_err()
                        && (dropping_txs.contains(&i) || reverting_txs.contains(&i))
                    {
                        // The transaction might have been invalidated by another one, so we drop it
                        included_txs[i] = false;
                    } else {
                        // The error isn't transaction-related, so we just drop this bundle
                        return (false, 0, vec![], evm.into_db());
                    }
                }
            };
        }
        (true, gas_used_in_bundle, included_txs, evm.into_db())
    }

    fn sign_transaction(&self, tx: TxEip1559) -> Result<RecoveredTx<E>, ValidationApiError> {
        let signature = self
            .merger_signer
            .sign_hash_sync(&tx.signature_hash())
            .expect("signer is local and private key is valid");
        let signed_tx = tx.into_signed(signature);

        // We encode and decode the transaction to turn it into the same SignedTx type expected by the type bounds
        let mut buf = vec![];
        signed_tx.encode_2718(&mut buf);
        let signed_tx = SignedTx::<E>::decode_2718(&mut buf.as_slice())
            .expect("we just encoded it with encode_2718");
        let recovered_signed_tx = Recovered::new_unchecked(signed_tx, self.merger_signer.address());
        Ok(recovered_signed_tx)
    }

    fn assemble_block<'a, DB>(
        &self,
        block_executor: impl BlockExecutorFor<'a, <E as ConfigureEvm>::BlockExecutorFactory, DB>,
        state_provider: &dyn StateProvider,
        recovered_txs: Vec<RecoveredTx<E>>,
        withdrawals_opt: Option<Withdrawals>,
        parent_header: reth_primitives::SealedHeader<
            <<E as ConfigureEvm>::Primitives as NodePrimitives>::BlockHeader,
        >,
        old_header: Header,
    ) -> Result<(RecoveredBlockFor<E>, Requests), ValidationApiError>
    where
        DB: Database + core::fmt::Debug + 'a,
        DB::Error: Send + Sync + 'static,
    {
        let chain_spec = self.provider.chain_spec();

        // This part was taken from `reth_evm::execute::BasicBlockBuilder::finish()`.
        // Using the `BlockBuilder` trait erases the DB type and makes transaction
        // simulation or value estimation impossible, so we have to re-implement
        // the block building ourselves.
        let (evm, result) = block_executor.finish()?;
        let (db, evm_env) = evm.finish();

        // merge all transitions into bundle state
        db.merge_transitions(BundleRetention::Reverts);

        // calculate the state root
        let hashed_state = state_provider.hashed_post_state(&db.bundle_state);
        let (state_root, _trie_updates) = state_provider
            .state_root_with_updates(hashed_state.clone())
            .map_err(BlockExecutionError::other)?;

        let (transactions, senders): (Vec<_>, Vec<_>) =
            recovered_txs.into_iter().map(|tx| tx.into_parts()).unzip();

        // Taken from `reth_evm_ethereum::build::EthBlockAssembler::assemble_block()`.
        // The function receives an unbuildable `BlockAssemblerInput`, due to being
        // marked as non-exhaustive and having no constructors.
        let timestamp = evm_env.block_env.timestamp.saturating_to();

        let transactions_root = proofs::calculate_transaction_root(&transactions);

        // Had to inline this manually due to generics
        // let receipts_root = Receipt::calculate_receipt_root_no_memo(result.receipts);
        let receipts_root = ordered_trie_root_with_encoder(&result.receipts, |r, buf| {
            r.with_bloom_ref().encode_2718(buf)
        });
        let logs_bloom = logs_bloom(result.receipts.iter().flat_map(|r| r.logs()));

        let withdrawals = chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(|| withdrawals_opt.unwrap_or_default());

        let withdrawals_root = withdrawals
            .as_deref()
            .map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash = chain_spec
            .is_prague_active_at_timestamp(timestamp)
            .then(|| result.requests.requests_hash());

        let mut excess_blob_gas = None;
        let mut blob_gas_used = None;

        // only determine cancun fields when active
        if chain_spec.is_cancun_active_at_timestamp(timestamp) {
            blob_gas_used = Some(
                transactions
                    .iter()
                    .map(|tx| tx.blob_gas_used().unwrap_or_default())
                    .sum(),
            );
            excess_blob_gas = if chain_spec.is_cancun_active_at_timestamp(parent_header.timestamp())
            {
                parent_header.maybe_next_block_excess_blob_gas(
                    chain_spec.blob_params_at_timestamp(timestamp),
                )
            } else {
                // for the first post-fork block, both parent.blob_gas_used and
                // parent.excess_blob_gas are evaluated as 0
                Some(alloy_eips::eip7840::BlobParams::cancun().next_block_excess_blob_gas(0, 0))
            };
        }

        let header = Header {
            parent_hash: old_header.parent_hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: evm_env.block_env.beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp,
            mix_hash: evm_env.block_env.prevrandao.unwrap_or_default(),
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(evm_env.block_env.basefee),
            number: evm_env.block_env.number.saturating_to(),
            gas_limit: evm_env.block_env.gas_limit,
            difficulty: evm_env.block_env.difficulty,
            gas_used: result.gas_used,
            extra_data: old_header.extra_data().clone(),
            parent_beacon_block_root: old_header.parent_beacon_block_root(),
            blob_gas_used,
            excess_blob_gas,
            requests_hash,
        };

        let block = Block {
            header,
            body: BlockBody {
                transactions,
                ommers: Default::default(),
                withdrawals,
            },
        };

        // Continuation from `BasicBlockBuilder::finish`
        Ok((
            RecoveredBlock::new_unhashed(block, senders),
            result.requests,
        ))
    }

    fn get_parent_header(
        &self,
        parent_hash: B256,
    ) -> Result<
        SealedHeader<<<E as ConfigureEvm>::Primitives as NodePrimitives>::BlockHeader>,
        ValidationApiError,
    > {
        let latest_header = self
            .provider
            .latest_header()?
            .ok_or_else(|| ValidationApiError::MissingLatestBlock)?;

        let parent_header = if parent_hash == latest_header.hash() {
            latest_header
        } else {
            // parent is not the latest header so we need to fetch it and ensure it's not too old
            let parent_header = self
                .provider
                .sealed_header_by_hash(parent_hash)?
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
        Ok(parent_header)
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
            let result = Self::validate_builder_submission_v3(&this, request).await;
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
            let result = Self::validate_builder_submission_v4(&this, request).await;
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
            let result = Self::merge_block_v1(&this, request).await;
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
    /// Configuration for revenue distribution.
    distribution_config: DistributionConfig,
    /// Whether to validate merged blocks or not
    validate_merged_blocks: bool,
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
    pub relay_fee_recipient: Address,
    /// Configuration for revenue distribution.
    pub distribution_config: DistributionConfig,
    /// The address of the contract used to distribute rewards.
    /// It must have a `disperseEther(address[],uint256[])` function.
    pub distribution_contract: Address,
    /// Whether to validate merged blocks or not
    pub validate_merged_blocks: bool,
}

/// Default validation blocks window of 3 blocks
pub const DEFAULT_VALIDATION_WINDOW: u64 = 3;

impl Default for ValidationApiConfig {
    fn default() -> Self {
        Self {
            blacklist_endpoint: Default::default(),
            validation_window: DEFAULT_VALIDATION_WINDOW,
            merger_private_key: String::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            relay_fee_recipient: address!("0x0000000000000000000000000000000000000000"),
            distribution_config: DistributionConfig::default(),
            // Address of `Disperse.app` contract
            // https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150
            distribution_contract: address!("0xD152f549545093347A162Dce210e7293f1452150"),
            validate_merged_blocks: true,
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
    #[error("could not find a proposer payment tx")]
    MissingProposerPayment,
    #[error("revenue allocation tx reverted")]
    RevenueAllocationReverted,
    #[error("proposer payment tx reverted")]
    ProposerPaymentReverted,
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
            | ValidationApiError::MissingProposerPayment
            | ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

            ValidationApiError::MissingLatestBlock
            | ValidationApiError::MissingParentBlock
            | ValidationApiError::BlockTooOld
            | ValidationApiError::NextEvmEnvFail
            | ValidationApiError::NextBuilderFail
            | ValidationApiError::RevenueAllocationReverted
            | ValidationApiError::ProposerPaymentReverted
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
    pub const fn _empty() -> Self {
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
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MergeableOrder {
    Tx(MergeableTransaction),
    Bundle(MergeableBundle),
}

impl MergeableOrder {
    fn transactions(&self) -> &[Bytes] {
        match self {
            MergeableOrder::Tx(tx) => std::slice::from_ref(&tx.transaction),
            MergeableOrder::Bundle(bundle) => &bundle.transactions,
        }
    }

    fn reverting_txs(&self) -> &[usize] {
        match self {
            MergeableOrder::Tx(tx) if tx.can_revert => &[0],
            MergeableOrder::Tx(_) => &[],
            MergeableOrder::Bundle(bundle) => &bundle.reverting_txs,
        }
    }

    fn dropping_txs(&self) -> &[usize] {
        match self {
            MergeableOrder::Tx(_) => &[],
            MergeableOrder::Bundle(bundle) => &bundle.dropping_txs,
        }
    }
}

impl From<MergeableTransaction> for MergeableOrder {
    fn from(tx: MergeableTransaction) -> Self {
        MergeableOrder::Tx(tx)
    }
}

impl From<MergeableBundle> for MergeableOrder {
    fn from(bundle: MergeableBundle) -> Self {
        MergeableOrder::Bundle(bundle)
    }
}

/// Represents a single transaction to be appended into a block atomically.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeableTransaction {
    /// Transaction that can be merged into the block.
    pub transaction: Bytes,
    /// Txs that may revert.
    pub can_revert: bool,
}

/// Represents a bundle of transactions to be appended into a block atomically.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct MergeableBundle {
    /// List of transactions that can be merged into the block.
    pub transactions: Vec<Bytes>,
    /// Txs that may revert.
    pub reverting_txs: Vec<usize>,
    /// Txs that are allowed to be omitted, but not revert.
    pub dropping_txs: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeableOrderWithOrigin {
    /// Address of the builder that submitted this order.
    pub origin: Address,
    /// Mergeable order.
    pub order: MergeableOrder,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeBlockRequestV1 {
    /// The original payload value
    pub original_value: U256,
    /// The address to send the proposer payment to.
    pub proposer_fee_recipient: Address,
    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
    pub execution_payload: ExecutionPayloadV3,
    pub merging_data: Vec<MergeableOrderWithOrigin>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBlockResponseV1 {
    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
    pub execution_payload: ExecutionPayloadV3,
    pub execution_requests: ExecutionRequestsV4,
    /// Indices for orders that contains blobs.
    /// The second value is the index of the tx inside the bundle.
    pub appended_blob_order_indices: Vec<(usize, usize)>,
    /// Total value for the proposer
    pub proposer_value: U256,
}

/// Block validation rpc interface.
#[rpc(server, namespace = "relay")]
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

/// Recovers transactions from a bundle
fn recover_transactions<E>(order: &MergeableOrder) -> Result<Vec<RecoveredTx<E>>, alloy_rlp::Error>
where
    E: ConfigureEvm,
{
    order
        .transactions()
        .iter()
        .map(|b| {
            let mut buf = b.as_ref();
            let tx = <SignedTx<E> as Decodable2718>::decode_2718(&mut buf)?;
            if !buf.is_empty() {
                return Err(alloy_rlp::Error::UnexpectedLength);
            }
            let recovered = tx
                .try_into_recovered()
                .or(Err(alloy_rlp::Error::Custom("invalid signature")))?;
            Ok(recovered)
        })
        .collect()
}

/// Encodes a call to `disperseEther(address[],uint256[])` with the given recipients and values.
fn encode_disperse_eth_calldata<'a, I, It>(input: I) -> Vec<u8>
where
    I: IntoIterator<Item = (&'a Address, &'a U256), IntoIter = It>,
    It: ExactSizeIterator<Item = I::Item> + Clone,
{
    let iter = input.into_iter();
    let len = iter.len();
    let mut calldata = Vec::with_capacity(4 + 64 + len * 32 * 2);
    // selector for "disperseEther(address[],uint256[])"
    calldata.extend_from_slice(&[0xe6, 0x3d, 0x38, 0xed]);
    // Offset for recipients from start of calldata (without counting selector)
    // 32 bytes for each offset = 64
    let recipients_offset: [u8; 32] = U256::from(64).to_be_bytes();
    calldata.extend_from_slice(&recipients_offset);
    // Offset for values from start of calldata (without counting selector)
    // 32 bytes for each offset + 32 bytes for recipients length + 32 bytes for each recipient
    let values_offset: [u8; 32] = (U256::from(64 + 32 + len * 32)).to_be_bytes();
    calldata.extend_from_slice(&values_offset);

    let revenues_length: [u8; 32] = U256::from(len).to_be_bytes();
    calldata.extend_from_slice(&revenues_length);

    calldata.extend(iter.clone().flat_map(|(recipient, _)| {
        let mut arr = [0_u8; 32];
        arr[12..].copy_from_slice(recipient.as_slice());
        arr
    }));

    calldata.extend_from_slice(&revenues_length);

    calldata.extend(iter.flat_map(|(_, value)| value.to_be_bytes::<32>()));
    calldata
}

/// Configuration for revenue distribution among different parties.
#[derive(Debug, Serialize, Eq, PartialEq, Deserialize, Clone)]
pub struct DistributionConfig {
    /// Total number of base points to distribute.
    /// Each participant will be paid `revenue * x / total_bips`.
    total_bips: u64,
    /// Base points allocated to the relay.
    relay_bips: u64,
    /// Base points allocated to the proposer.
    proposer_bips: u64,
    /// Base points allocated to the builder.
    builder_bips: u64,
    /// Base points allocated to the winning builder.
    winning_builder_bips: u64,
}

impl Default for DistributionConfig {
    fn default() -> Self {
        let total_bips = 10000;
        let relay_bips = total_bips / 4;
        let proposer_bips = total_bips / 4;
        let builder_bips = total_bips / 4;
        let winning_builder_bips = total_bips / 4;

        Self {
            total_bips,
            relay_bips,
            proposer_bips,
            builder_bips,
            winning_builder_bips,
        }
    }
}

impl DistributionConfig {
    fn split(&self, bips: u64, revenue: U256) -> U256 {
        (U256::from(bips) * revenue) / U256::from(self.total_bips)
    }

    fn relay_split(&self, revenue: U256) -> U256 {
        self.split(self.relay_bips, revenue)
    }

    fn proposer_split(&self, revenue: U256) -> U256 {
        self.split(self.proposer_bips, revenue)
    }

    fn builder_split(&self, revenue: U256) -> U256 {
        self.split(self.builder_bips, revenue)
    }
}

fn split_revenue(
    distribution_config: &DistributionConfig,
    revenues: HashMap<Address, U256>,
    relay_fee_recipient: Address,
    proposer_fee_recipient: Address,
) -> (U256, HashMap<Address, U256>) {
    let mut updated_revenues = HashMap::with_capacity(revenues.len());

    let mut distributed_value = U256::ZERO;

    // We divide the revenue among the winning builder, proposer, flow origin, and the relay.
    // We assume the winning builder controls the beneficiary address, and so it will receive any undistributed revenue.
    for (origin, revenue) in revenues {
        let relay_revenue = distribution_config.relay_split(revenue);
        updated_revenues
            .entry(relay_fee_recipient)
            .and_modify(|v| *v += relay_revenue)
            .or_insert(relay_revenue);

        let proposer_revenue = distribution_config.proposer_split(revenue);
        updated_revenues
            .entry(proposer_fee_recipient)
            .and_modify(|v| *v += proposer_revenue)
            .or_insert(proposer_revenue);

        let builder_revenue = distribution_config.builder_split(revenue);
        updated_revenues
            .entry(origin)
            .and_modify(|v| *v += builder_revenue)
            .or_insert(builder_revenue);

        distributed_value += builder_revenue + relay_revenue + proposer_revenue;
    }

    (distributed_value, updated_revenues)
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
        // This map is for turning tuple references into references of tuples
        let actual = encode_disperse_eth_calldata(input.iter().map(|(a, v)| (a, v)));
        assert_eq!(actual, expected);
    }
}
