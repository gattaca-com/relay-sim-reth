use alloy_consensus::{
    BlobTransactionValidationError, BlockHeader, EnvKzgSettings, Header, Transaction, TxEnvelope,
    TxReceipt,
};
use alloy_eips::{eip4844::kzg_to_versioned_hash, eip7685::RequestsOrHash};
use alloy_rlp::Decodable;
use alloy_rpc_types_beacon::relay::{
    BidTrace, BuilderBlockValidationRequest, BuilderBlockValidationRequestV2,
    BuilderBlockValidationRequestV3, BuilderBlockValidationRequestV4,
};
use alloy_rpc_types_engine::{
    BlobsBundleV1, CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    PraguePayloadFields,
};
use async_trait::async_trait;
use bytes::Bytes;
use core::fmt;
use dashmap::DashSet;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{core::RpcResult, types::ErrorObject};
use reth_ethereum::evm::primitives::block::BlockExecutor;
use reth_ethereum::evm::primitives::execute::BlockBuilder;
use reth_ethereum::{
    chainspec::EthereumHardforks,
    consensus::{ConsensusError, FullConsensus},
    evm::{
        primitives::{Evm, RecoveredTx, block::BlockExecutionError, execute::Executor},
        revm::{cached::CachedReads, database::StateProviderDatabase},
    },
    node::core::rpc::result::{internal_rpc_err, invalid_params_rpc_err},
    pool::PoolPooledTx,
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
use revm::{
    Database, DatabaseRef,
    database::{CacheDB, State},
};
use revm_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
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
        } = config;
        let disallow = Arc::new(DashSet::new());

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
        registered_gas_limit: u64,
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
    async fn merge_block_v1(&self, request: MergeBlockRequestV1) -> Result<(), ValidationApiError> {
        info!(target: "rpc::relay", "Merging block v1");
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

        let (sealed_block, senders) = block.split();
        let (header, body) = sealed_block.split();

        let body = body.into_ethereum_body();
        let (withdrawals, transactions) = (body.withdrawals, body.transactions);

        // TODO: load from configuration
        let beneficiary = Address::from_slice(b"");

        // We'll create a new block with ourselves as the beneficiary/coinbase
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

        let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));

        let mut state_db = State::builder().with_database(cached_db).build();
        // Execute the base block
        let mut builder = self
            .evm_config
            .builder_for_next_block(&mut state_db, &parent_header, new_block_attrs)
            .unwrap();

        builder.apply_pre_execution_changes().unwrap();

        // Insert the transactions from the unmerged block
        for (tx, sender) in transactions.into_iter().zip(senders) {
            // NOTE: we use the senders from the block body, which should be correct
            builder
                .execute_transaction(Recovered::new_unchecked(tx, sender))
                .unwrap();
        }

        // Append transactions until we run out of space
        for (origin, bundle) in request
            .merging_data
            .into_iter()
            .flat_map(|mb| mb.bundles.into_iter().map(move |b| (mb.origin, b)))
        {
            for tx in bundle.transactions {}
            // Execute the transaction
        }

        let outcome = builder.finish(&state_provider)?;
        // TODO: return block
        let block = outcome.block;

        Ok(())
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
    async fn merge_block_v1(&self, request: MergeBlockRequestV1) -> jsonrpsee::core::RpcResult<()> {
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
}

impl ValidationApiConfig {
    /// Default validation blocks window of 3 blocks
    pub const DEFAULT_VALIDATION_WINDOW: u64 = 3;

    pub fn new(blacklist_endpoint: String) -> Self {
        Self {
            blacklist_endpoint,
            validation_window: Self::DEFAULT_VALIDATION_WINDOW,
        }
    }
}

impl Default for ValidationApiConfig {
    fn default() -> Self {
        Self {
            blacklist_endpoint: Default::default(),
            validation_window: Self::DEFAULT_VALIDATION_WINDOW,
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
            | ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

            ValidationApiError::MissingLatestBlock
            | ValidationApiError::MissingParentBlock
            | ValidationApiError::BlockTooOld
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
    #[serde(flatten)]
    pub base: BuilderBlockValidationRequestV4,
    #[serde(default)]
    pub merging_data: Vec<MergeableBundles>,
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
    async fn merge_block_v1(&self, request: MergeBlockRequestV1) -> jsonrpsee::core::RpcResult<()>;
}
