use std::collections::{HashMap, HashSet};

use alloy_consensus::{BlockHeader, SignableTransaction, Transaction, TxEip1559};
use alloy_eips::{eip7685::RequestsOrHash, eip7840::BlobParams};
use alloy_rpc_types_beacon::{relay::BidTrace, requests::ExecutionRequestsV4};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV3,
    PraguePayloadFields,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, sol};
use reth_ethereum::{
    Block, EthPrimitives,
    chainspec::EthChainSpec,
    evm::{
        EthEvmConfig,
        primitives::{
            Evm, EvmEnvFor, EvmError,
            block::{BlockExecutionError, BlockExecutor},
            execute::BlockBuilder as RethBlockBuilder,
        },
        revm::{cached::CachedReads, database::StateProviderDatabase},
    },
    provider::ChainSpecProvider,
    storage::{StateProvider, StateProviderFactory},
    trie::{
        iter::{IntoParallelIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};
use reth_node_builder::{Block as _, ConfigureEvm, NewPayloadError, NextBlockEnvAttributes, PayloadValidator};
use reth_primitives::{GotExpected, Recovered};
use revm::{
    DatabaseCommit, DatabaseRef,
    database::{CacheDB, State},
};
use revm_primitives::{Address, B256, U256, alloy_primitives::TxHash};
use tracing::info;

pub(crate) use crate::block_merging::api::{BlockMergingApi, BlockMergingApiServer};
use crate::{
    block_merging::{
        error::BlockMergingApiError,
        types::{
            BlockMergeRequestV1, BlockMergeResponseV1, DistributionConfig, MergeableOrderBytes,
            MergeableOrderRecovered, RecoveredTx, SignedTx, SimulatedOrder, SimulationError,
        },
    },
    common::CachedRethDb,
};

mod api;
mod error;
pub(crate) mod types;

impl BlockMergingApi {
    /// Core logic for appending additional transactions to a block.
    async fn merge_block_v1(&self, request: BlockMergeRequestV1) -> Result<BlockMergeResponseV1, BlockMergingApiError> {
        let block: Block = request.execution_payload.try_into_block().map_err(NewPayloadError::Eth)?;

        let proposer_fee_recipient = request.proposer_fee_recipient;
        let gas_limit = block.gas_limit;
        let parent_beacon_block_root = block.parent_beacon_block_root().unwrap();

        // The `merge_block` function is to avoid a lifetime leak that causes this
        // async fn to not be Send, which is required for spawning it.
        let (response, blob_versioned_hashes, request_cache) =
            self.merge_block(request.original_value, proposer_fee_recipient, block, request.merging_data).await?;

        let parent_hash = response.execution_payload.payload_inner.payload_inner.parent_hash;

        self.validation.update_cached_reads(parent_hash, request_cache).await;

        if self.validate_merged_blocks {
            let block_hash = response.execution_payload.payload_inner.payload_inner.block_hash;
            let gas_used = response.execution_payload.payload_inner.payload_inner.gas_used;

            let message = BidTrace {
                slot: 0, // unused
                parent_hash,
                block_hash,
                builder_pubkey: Default::default(),  // unused
                proposer_pubkey: Default::default(), // unused
                proposer_fee_recipient,
                gas_limit,
                gas_used,
                value: response.proposer_value,
            };
            let block = self.validation.payload_validator.ensure_well_formed_payload(ExecutionData {
                payload: ExecutionPayload::V3(response.execution_payload.clone()),
                sidecar: ExecutionPayloadSidecar::v4(
                    CancunPayloadFields { parent_beacon_block_root, versioned_hashes: blob_versioned_hashes },
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(response.execution_requests.to_requests()),
                    },
                ),
            })?;

            self.validation.validate_message_against_block(block, message, 0, false, None).await?;
        }

        Ok(response)
    }

    /// Merge a block by appending mergeable orders.
    /// Returns the response with the block, the versioned hashes of the appended blobs,
    /// and the cached reads used during execution.
    async fn merge_block(
        &self,
        original_value: U256,
        proposer_fee_recipient: Address,
        base_block: Block,
        merging_data: Vec<MergeableOrderBytes>,
    ) -> Result<(BlockMergeResponseV1, Vec<B256>, CachedReads), BlockMergingApiError> {
        info!(target: "rpc::relay", "Merging block v1");
        let validation = &self.validation;
        let evm_config = &validation.evm_config;

        // Recover the base block transactions in parallel
        let (base_block, senders) =
            base_block.try_into_recovered().map_err(|_| BlockMergingApiError::InvalidSignatureInBaseBlock)?.split();

        let (header, body) = base_block.split();

        let (withdrawals, transactions) = (body.withdrawals, body.transactions);

        let block_base_fee_per_gas = header.base_fee_per_gas.unwrap_or_default();

        let relay_fee_recipient = self.relay_fee_recipient;
        let beneficiary = header.beneficiary;

        // Check we have collateral for this builder
        let Some(types::PrivateKeySigner(signer)) = self.builder_collateral_map.get(&beneficiary).as_ref() else {
            return Err(BlockMergingApiError::NoSignerForBuilder(beneficiary));
        };

        // Check that block has proposer payment, otherwise reject it.
        // We don't remove it from the block, but add another payment transaction at the end.
        let Some(payment_tx) = transactions.last() else {
            return Err(BlockMergingApiError::MissingProposerPayment);
        };
        if payment_tx.value() != original_value || payment_tx.to() != Some(proposer_fee_recipient) {
            return Err(BlockMergingApiError::InvalidProposerPayment);
        }

        let payment_tx_gas_limit = payment_tx.gas_limit();

        // Leave some gas for the final revenue distribution call
        // and the proposer payment.
        // The gas cost should be 10k per target, but could jump
        // to 35k if the targets are new accounts.
        // This number leaves us space for ~9 non-empty targets, or ~2 new accounts.
        // TODO: compute dynamically by keeping track of gas cost
        let distribution_gas_limit = 100000;
        // We also leave some gas for the final proposer payment
        let gas_limit = header
            .gas_limit
            .checked_sub(distribution_gas_limit + payment_tx_gas_limit)
            .ok_or(BlockMergingApiError::NotEnoughGasForPayment(header.gas_limit))?;

        let new_block_attrs = NextBlockEnvAttributes {
            timestamp: header.timestamp,
            suggested_fee_recipient: beneficiary,
            // mix_hash == prev_randao (source: https://eips.ethereum.org/EIPS/eip-4399)
            prev_randao: header.mix_hash,
            gas_limit: header.gas_limit,
            parent_beacon_block_root: header.parent_beacon_block_root,
            withdrawals,
        };

        let parent_hash = header.parent_hash;

        let state_provider = validation.provider.state_by_block_hash(parent_hash)?;

        let mut request_cache = validation.cached_reads(parent_hash).await;

        let cached_db = request_cache.as_db(StateProviderDatabase::new(&state_provider));

        let mut state_db = State::builder().with_database_ref(&cached_db).build();

        let parent_header = validation.get_parent_header(parent_hash)?;

        // Execute the base block
        let evm_env =
            evm_config.next_evm_env(&parent_header, &new_block_attrs).or(Err(BlockMergingApiError::NextEvmEnvFail))?;

        let evm = evm_config.evm_with_env(&mut state_db, evm_env.clone());
        let ctx = evm_config.context_for_next_block(&parent_header, new_block_attrs.clone());

        let block_builder = evm_config.create_block_builder(evm, &parent_header, ctx);

        let mut builder = BlockBuilder::new(evm_config.clone(), evm_env, block_builder, gas_limit);

        // Pair the transactions with the precomputed senders
        let recovered_txs =
            transactions.into_iter().zip(senders).map(|(tx, sender)| RecoveredTx::new_unchecked(tx, sender));
        builder.execute_base_block(recovered_txs)?;

        let recovered_orders: Vec<MergeableOrderRecovered> =
            merging_data.into_par_iter().filter_map(|order| order.recover().ok()).collect();

        // TODO: parallelize simulation
        // For this we need to consolidate `State` and wrap our database in a thread-safe cache.
        let mut simulated_orders: Vec<SimulatedOrder> =
            recovered_orders.into_iter().filter_map(|order| builder.simulate_order(order).ok()).collect();

        // Sort orders by revenue, in descending order
        simulated_orders.par_sort_unstable_by(|o1, o2| o2.builder_payment.cmp(&o1.builder_payment));

        let initial_builder_balance = get_balance_or_zero(builder.get_state(), beneficiary)?;

        // Simulate orders until we run out of block gas
        let revenues = append_greedily_until_gas_limit(&mut builder, simulated_orders)?;

        let final_builder_balance = get_balance_or_zero(builder.get_state(), beneficiary)?;

        let total_revenue: U256 = revenues.values().sum();
        let builder_balance_delta = final_builder_balance.saturating_sub(initial_builder_balance);

        // Sanity check the sum of revenues is equal to the builder balance delta
        if total_revenue != builder_balance_delta {
            return Err(BlockMergingApiError::BuilderBalanceDeltaMismatch(GotExpected {
                expected: total_revenue,
                got: builder_balance_delta,
            }));
        }

        let (proposer_added_value, distributed_value, updated_revenues) =
            prepare_revenues(&self.distribution_config, revenues, relay_fee_recipient, beneficiary);

        if proposer_added_value.is_zero() {
            return Err(BlockMergingApiError::ZeroProposerDelta);
        }

        self.append_payment_txs(
            &mut builder,
            signer,
            &updated_revenues,
            distributed_value,
            distribution_gas_limit,
            block_base_fee_per_gas.into(),
            payment_tx_gas_limit,
            proposer_fee_recipient,
            proposer_added_value,
        )?;

        let built_block = builder.finish(&state_provider)?;

        let response = BlockMergeResponseV1 {
            execution_payload: built_block.execution_payload,
            execution_requests: built_block.execution_requests,
            appended_blobs: built_block.appended_blob_versioned_hashes,
            proposer_value: proposer_added_value + original_value,
        };
        Ok((response, built_block.blob_versioned_hashes, request_cache))
    }

    #[expect(clippy::too_many_arguments)]
    fn append_payment_txs<'a, BB, Ex, Ev>(
        &self,
        builder: &mut BlockBuilder<BB>,
        signer: &PrivateKeySigner,
        updated_revenues: &HashMap<Address, U256>,
        distributed_value: U256,
        distribution_gas_limit: u64,
        block_base_fee_per_gas: u128,
        payment_tx_gas_limit: u64,
        proposer_fee_recipient: Address,
        proposer_payment_value: U256,
    ) -> Result<(), BlockMergingApiError>
    where
        BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
        Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'a,
        Ev: Evm<DB = &'a mut CachedRethDb<'a>> + 'a,
    {
        let calldata = encode_disperse_eth_calldata(updated_revenues);

        // Get the chain ID from the configured provider
        let chain_id = self.validation.provider.chain_spec().chain_id();

        // Get the chain ID from the configured provider
        let signer_address = signer.address();

        let Some(signer_info) = builder.get_state().basic_ref(signer_address)? else {
            return Err(BlockMergingApiError::EmptyBuilderSignerAccount(signer_address));
        };
        let total_payment_value = distributed_value + proposer_payment_value;

        if signer_info.balance < total_payment_value {
            return Err(BlockMergingApiError::NoBalanceInBuilderSigner {
                address: signer_address,
                current: signer_info.balance,
                required: total_payment_value,
            });
        }
        let nonce = signer_info.nonce + 1;

        let disperse_tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: distribution_gas_limit,
            max_fee_per_gas: block_base_fee_per_gas,
            max_priority_fee_per_gas: 0,
            to: self.disperse_address.into(),
            value: distributed_value,
            access_list: Default::default(),
            input: calldata.into(),
        };

        let signed_disperse_tx = sign_transaction(signer, disperse_tx)?;

        // Execute the disperse transaction
        let is_success = builder.append_transaction(signed_disperse_tx)?;

        if !is_success {
            return Err(BlockMergingApiError::RevenueAllocationReverted);
        }

        // Add proposer payment tx
        let proposer_payment_tx = TxEip1559 {
            chain_id,
            nonce: nonce + 1,
            gas_limit: payment_tx_gas_limit,
            max_fee_per_gas: block_base_fee_per_gas,
            max_priority_fee_per_gas: 0,
            to: proposer_fee_recipient.into(),
            value: proposer_payment_value,
            access_list: Default::default(),
            input: Default::default(),
        };

        let signed_proposer_payment_tx = sign_transaction(signer, proposer_payment_tx)?;

        let is_success = builder.append_transaction(signed_proposer_payment_tx)?;

        if !is_success {
            return Err(BlockMergingApiError::ProposerPaymentReverted);
        }

        Ok(())
    }
}

fn sign_transaction(signer: &PrivateKeySigner, tx: TxEip1559) -> Result<RecoveredTx, BlockMergingApiError> {
    let signature = signer.sign_hash_sync(&tx.signature_hash()).expect("signer is local and private key is valid");
    let signed_tx: SignedTx = tx.into_signed(signature).into();
    let recovered_signed_tx = Recovered::new_unchecked(signed_tx, signer.address());
    Ok(recovered_signed_tx)
}

/// Encodes a call to `disperseEther(address[],uint256[])` with the given recipients and values.
pub(crate) fn encode_disperse_eth_calldata(value_by_recipient: &HashMap<Address, U256>) -> Vec<u8> {
    sol! {
        function disperseEther(address[] recipients, uint256[] values) external payable;
    }

    let (recipients, values) = value_by_recipient.iter().unzip();

    disperseEtherCall { recipients, values }.abi_encode()
}

/// Computes revenue distribution, splitting merged block revenue to the multiple participants.
/// Returns the proposer value, the distributed value to other parties, and the
/// revenue to be distributed to each address.
pub(crate) fn prepare_revenues(
    distribution_config: &DistributionConfig,
    revenues: HashMap<Address, U256>,
    relay_fee_recipient: Address,
    block_beneficiary: Address,
) -> (U256, U256, HashMap<Address, U256>) {
    let mut updated_revenues = HashMap::with_capacity(revenues.len());

    let mut distributed_value = U256::ZERO;
    let mut proposer_added_value = U256::ZERO;

    // We divide the revenue among the winning builder, proposer, flow origin, and the relay.
    // We assume the winning builder controls the beneficiary address, and so it will receive any undistributed revenue.
    for (origin, revenue) in revenues {
        // Compute the revenue for the relay and bundle origin
        let relay_revenue = distribution_config.relay_split(revenue);
        updated_revenues.entry(relay_fee_recipient).and_modify(|v| *v += relay_revenue).or_insert(relay_revenue);

        let builder_revenue = distribution_config.merged_builder_split(revenue);
        updated_revenues.entry(origin).and_modify(|v| *v += builder_revenue).or_insert(builder_revenue);

        // Add both to the total value to be distributed
        distributed_value += builder_revenue + relay_revenue;

        // Add proposer revenue to the proposer added value
        proposer_added_value += distribution_config.proposer_split(revenue);
    }

    // Just in case, we remove the beneficiary address from the distribution and update the total
    distributed_value -= updated_revenues.remove(&block_beneficiary).unwrap_or(U256::ZERO);

    (proposer_added_value, distributed_value, updated_revenues)
}

struct BlockBuilder<BB> {
    block_builder: BB,

    // We need these to simulate orders
    evm_config: EthEvmConfig,
    evm_env: EvmEnvFor<EthEvmConfig>,
    blob_params: BlobParams,

    // Block builder keeps track of gas used, but it doesn't expose it
    // so we need to track it ourselves.
    gas_used: u64,
    // We use a custom gas limit, lower than the block gas limit,
    // to leave some gas for the final distribution and proposer payment txs.
    gas_limit: u64,

    /// Transaction hashes for the transactions in the block.
    tx_hashes: HashSet<TxHash>,
    /// Blob versioned hashes for the transactions in the block, including
    /// those in [Self::appended_blob_versioned_hashes].
    /// Used for optional block validation.
    blob_versioned_hashes: Vec<B256>,
    /// Blob versioned hashes for the transactions that were appended.
    appended_blob_versioned_hashes: Vec<B256>,
}

impl<'a, BB, Ex, Ev> BlockBuilder<BB>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'a,
    Ev: Evm<DB = &'a mut CachedRethDb<'a>> + 'a,
{
    fn new(evm_config: EthEvmConfig, evm_env: EvmEnvFor<EthEvmConfig>, block_builder: BB, gas_limit: u64) -> Self {
        let timestamp: u64 = evm_env.block_env.timestamp.try_into().expect("all unix timestamps fit in an u64");
        let blob_params = evm_config.chain_spec().blob_params_at_timestamp(timestamp).expect("we are past Cancun");
        Self {
            block_builder,
            evm_config,
            evm_env,
            blob_params,
            gas_used: 0,
            gas_limit,
            tx_hashes: Default::default(),
            blob_versioned_hashes: Default::default(),
            appended_blob_versioned_hashes: Default::default(),
        }
    }

    fn execute_base_block(
        &mut self,
        txs: impl ExactSizeIterator<Item = RecoveredTx>,
    ) -> Result<(), BlockExecutionError> {
        self.block_builder.apply_pre_execution_changes()?;

        // Keep track of already applied txs, to discard duplicates
        self.tx_hashes = HashSet::with_capacity(txs.len());

        // Insert the transactions from the unmerged block
        for tx in txs {
            self.tx_hashes.insert(*tx.tx_hash());

            if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                self.blob_versioned_hashes.extend(versioned_hashes);
            }
            self.gas_used += self.block_builder.execute_transaction(tx)?;
        }

        Ok(())
    }

    fn get_state(&self) -> &CachedRethDb<'a> {
        self.block_builder.executor().evm().db()
    }

    fn was_already_applied(&self, tx_hash: &TxHash) -> bool {
        self.tx_hashes.contains(tx_hash)
    }

    fn simulate_order(&self, order: MergeableOrderRecovered) -> Result<SimulatedOrder, SimulationError> {
        let dropping_txs = order.dropping_txs();

        // Check for undroppable duplicate transactions
        let any_duplicate_undroppable_txs = order
            .transactions()
            .iter()
            .enumerate()
            .any(|(i, tx)| self.was_already_applied(tx.tx_hash()) && dropping_txs.contains(&i));

        if any_duplicate_undroppable_txs {
            return Err(SimulationError::DuplicateTransaction);
        }

        let available_gas = self.gas_limit - self.gas_used;
        let available_blobs = self.blob_params.max_blob_count - self.blob_versioned_hashes.len() as u64;

        let evm_env = self.evm_env.clone();
        let state = self.get_state();
        let simulated_order = simulate_order(&self.evm_config, state, evm_env, order, available_gas, available_blobs)?;
        // Check the order has some revenue
        if simulated_order.builder_payment.is_zero() {
            return Err(SimulationError::ZeroBuilderPayment);
        }
        // Check we have enough gas to include the order
        if self.gas_used + simulated_order.gas_used > self.gas_limit {
            return Err(SimulationError::OutOfBlockGas);
        }
        Ok(simulated_order)
    }

    fn append_transaction(&mut self, tx: RecoveredTx) -> Result<bool, BlockMergingApiError> {
        let mut is_success = false;
        let blobs_available = self.blob_params.max_blob_count - self.blob_versioned_hashes.len() as u64;
        // NOTE: we check this because the block builder doesn't seem to do it
        if tx.blob_count().unwrap_or(0) > blobs_available {
            return Err(BlockMergingApiError::BlobLimitReached);
        }
        self.gas_used +=
            self.block_builder.execute_transaction_with_result_closure(tx.clone(), |r| is_success = r.is_success())?;

        self.tx_hashes.insert(*tx.tx_hash());
        // If tx has blobs, store the order index and tx sub-index to add the blobs to the payload
        // Also store the versioned hash for validation
        if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
            self.blob_versioned_hashes.extend(versioned_hashes);
            self.appended_blob_versioned_hashes.extend(versioned_hashes);
        }
        Ok(is_success)
    }

    fn finish(self, state_provider: &dyn StateProvider) -> Result<BuiltBlock, BlockMergingApiError> {
        let blob_versioned_hashes = self.blob_versioned_hashes;
        let appended_blob_versioned_hashes = self.appended_blob_versioned_hashes;

        let outcome = self.block_builder.finish(state_provider)?;
        let execution_requests =
            outcome.execution_result.requests.try_into().or(Err(BlockMergingApiError::ExecutionRequests))?;

        let sealed_block = outcome.block.into_sealed_block();
        let block_hash = sealed_block.hash();
        let block = sealed_block.into_block().into_ethereum_block();

        let execution_payload = ExecutionPayloadV3::from_block_unchecked(block_hash, &block);

        let result =
            BuiltBlock { execution_payload, execution_requests, blob_versioned_hashes, appended_blob_versioned_hashes };
        Ok(result)
    }
}

struct BuiltBlock {
    execution_payload: ExecutionPayloadV3,
    execution_requests: ExecutionRequestsV4,
    /// Versioned hashes for the whole block
    blob_versioned_hashes: Vec<B256>,
    /// Versioned hashes for only the appended blobs
    appended_blob_versioned_hashes: Vec<B256>,
}

fn append_greedily_until_gas_limit<'a, BB, Ex, Ev>(
    builder: &mut BlockBuilder<BB>,
    simulated_orders: Vec<SimulatedOrder>,
) -> Result<HashMap<Address, U256>, BlockMergingApiError>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'a,
    Ev: Evm<DB = &'a mut CachedRethDb<'a>> + 'a,
{
    let mut revenues = HashMap::new();

    // Append transactions by score until we run out of space
    for simulated_order in simulated_orders {
        let order = simulated_order.order;
        let origin = *order.origin();

        let Ok(simulated_order) = builder.simulate_order(order) else {
            continue;
        };

        let SimulatedOrder { order, should_be_included, builder_payment, .. } = simulated_order;

        // Append the bundle

        // We can't avoid re-execution here due to the BlockBuilder API
        for (tx, _) in order.into_transactions().into_iter().zip(should_be_included).filter(|(_, sbi)| *sbi) {
            builder.append_transaction(tx)?;
        }

        // Update the revenue for the bundle's origin
        revenues.entry(origin).and_modify(|v| *v += builder_payment).or_insert(builder_payment);
    }
    Ok(revenues)
}

/// Simulates an order.
/// Returns whether the order is valid, the amount of gas used, and a list
/// marking whether to include a transaction of the order or not.
fn simulate_order<DBRef>(
    evm_config: &EthEvmConfig,
    db_ref: DBRef,
    evm_env: EvmEnvFor<EthEvmConfig>,
    order: MergeableOrderRecovered,
    available_gas: u64,
    available_blobs: u64,
) -> Result<SimulatedOrder, SimulationError>
where
    DBRef: DatabaseRef + core::fmt::Debug,
    DBRef::Error: Send + Sync + 'static,
    SimulationError: From<DBRef::Error>,
{
    // Wrap current state in cache to avoid mutating it
    let cached_db = CacheDB::new(db_ref);
    // Create a new EVM with the pre-state
    let mut evm = evm_config.evm_with_env(cached_db, evm_env);
    let initial_balance = get_balance_or_zero(evm.db(), evm.block.beneficiary)?;

    let txs = order.transactions();
    let reverting_txs = order.reverting_txs();
    let dropping_txs = order.dropping_txs();

    let mut gas_used = 0;
    let mut blobs_added = 0;
    let mut included_txs = vec![true; txs.len()];

    // Check the bundle can be included in the block
    for (i, tx) in txs.iter().enumerate() {
        let can_be_dropped = dropping_txs.contains(&i);
        let can_revert = reverting_txs.contains(&i);
        // If tx takes too much gas, try to drop it or fail
        if tx.gas_limit() > (available_gas - gas_used) {
            if !can_be_dropped {
                return Err(SimulationError::OutOfBlockGas);
            }
            included_txs[i] = false;
            continue;
        }
        // If tx exceeds blob limit, try to drop it or fail
        if tx.blob_count().unwrap_or(0) > (available_blobs - blobs_added) {
            if !can_be_dropped {
                return Err(SimulationError::OutOfBlockBlobs);
            }
            included_txs[i] = false;
            continue;
        }
        // Execute transaction
        match evm.transact(tx) {
            Ok(result) => {
                if result.result.is_success() || can_revert {
                    gas_used += result.result.gas_used();
                    blobs_added += tx.blob_count().unwrap_or(0);
                    // Apply the state changes to the simulated state
                    // Note that this only commits to the cache wrapper, not the underlying database
                    evm.db_mut().commit(result.state);
                } else {
                    // If tx reverted and is not allowed to, we check if it
                    // can be dropped instead, else we discard this bundle.
                    if can_be_dropped {
                        // Tx should be dropped
                        included_txs[i] = false;
                    } else {
                        return Err(SimulationError::RevertNotAllowed(i));
                    }
                }
            }
            Err(e) => {
                if e.is_invalid_tx_err() && (can_be_dropped || can_revert) {
                    // The transaction might have been invalidated by another one, so we drop it
                    included_txs[i] = false;
                } else {
                    // The error isn't transaction-related or tx can't be dropped, so we just drop this bundle
                    return Err(SimulationError::DropNotAllowed(i));
                }
            }
        };
    }
    let final_balance = get_balance_or_zero(evm.db(), evm.block.beneficiary)?;
    let builder_payment = final_balance.saturating_sub(initial_balance);
    Ok(SimulatedOrder { order, gas_used, should_be_included: included_txs, builder_payment })
}

fn get_balance_or_zero<DB: DatabaseRef>(db: DB, address: Address) -> Result<U256, <DB as DatabaseRef>::Error> {
    Ok(db.basic_ref(address)?.map_or(U256::ZERO, |info| info.balance))
}
