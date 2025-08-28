use std::collections::{HashMap, HashSet};

use alloy_consensus::{BlockHeader, SignableTransaction, Transaction, TxEip1559};
use alloy_eips::{Decodable2718, Encodable2718, eip7685::RequestsOrHash};
use alloy_rpc_types_beacon::{relay::BidTrace, requests::ExecutionRequestsV4};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV2,
    ExecutionPayloadV3, PraguePayloadFields,
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
    primitives::SignedTransaction,
    provider::ChainSpecProvider,
    storage::{StateProvider, StateProviderFactory},
    trie::{
        iter::{IntoParallelIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};
use reth_node_builder::{Block as _, ConfigureEvm, NewPayloadError, NextBlockEnvAttributes, PayloadValidator};
use reth_primitives::Recovered;
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

        let (header, body) = base_block.split();

        let (withdrawals, mut transactions) = (body.withdrawals, body.transactions);

        let block_base_fee_per_gas = header.base_fee_per_gas.unwrap_or_default();

        let relay_fee_recipient = self.relay_fee_recipient;
        let beneficiary = header.beneficiary;

        // check we have collateral for this builder
        let Some(types::PrivateKeySigner(signer)) = self.builder_collateral_map.get(&beneficiary).as_ref() else {
            return Err(BlockMergingApiError::ExecutionRequests);
        };

        // Check that block has proposer payment, otherwise reject it.
        // Also remove proposer payment, we'll later add our own
        let Some(payment_tx) = transactions.pop() else {
            return Err(BlockMergingApiError::MissingProposerPayment);
        };
        if payment_tx.value() != original_value || payment_tx.to() != Some(proposer_fee_recipient) {
            return Err(BlockMergingApiError::InvalidProposerPayment);
        }

        // Leave some gas for the final revenue distribution call
        // and the proposer payment.
        // The gas cost should be 10k per target, but could jump
        // to 35k if the targets are new accounts.
        // This number leaves us space for ~9 non-empty targets, or ~2 new accounts.
        // TODO: compute dynamically by keeping track of gas cost
        let max_distribution_gas = 100000;
        // We also leave some gas for the final proposer payment
        let gas_limit = header.gas_limit - max_distribution_gas - payment_tx.gas_limit();

        let new_block_attrs = NextBlockEnvAttributes {
            timestamp: header.timestamp,
            suggested_fee_recipient: beneficiary,
            prev_randao: header.difficulty.to_be_bytes().into(),
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

        builder.execute_base_block(transactions)?;

        let recovered_orders: Vec<MergeableOrderRecovered> =
            merging_data.into_par_iter().filter_map(|order| order.recover().ok()).collect();

        // TODO: parallelize simulation
        // For this we need to consolidate `State` and wrap our database in a thread-safe cache.
        let mut simulated_orders: Vec<SimulatedOrder> =
            recovered_orders.into_iter().filter_map(|order| builder.simulate_order(order).ok()).collect();

        // Sort orders by revenue, in descending order
        simulated_orders.par_sort_unstable_by(|o1, o2| o1.builder_payment.cmp(&o2.builder_payment).reverse());

        let revenues = append_greedily_until_gas_limit(&mut builder, simulated_orders)?;

        let (proposer_value, distributed_value, updated_revenues) =
            prepare_revenues(&self.distribution_config, revenues, relay_fee_recipient, original_value, beneficiary);

        self.append_payment_txs(
            &mut builder,
            signer,
            &updated_revenues,
            distributed_value,
            max_distribution_gas,
            block_base_fee_per_gas.into(),
            payment_tx.gas_limit(),
            proposer_fee_recipient,
            proposer_value,
        )?;

        let built_block = builder.finish(&state_provider)?;

        let response = BlockMergeResponseV1 {
            execution_payload: built_block.execution_payload,
            execution_requests: built_block.execution_requests,
            appended_blobs: built_block.appended_blob_versioned_hashes,
            proposer_value,
        };
        Ok((response, built_block.blob_versioned_hashes, request_cache))
    }

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
        proposer_value: U256,
    ) -> Result<(), BlockMergingApiError>
    where
        BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
        Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'a,
        Ev: Evm<DB = &'a mut CachedRethDb<'a>> + 'a,
    {
        let calldata = encode_disperse_eth_calldata(
            updated_revenues.keys().copied().collect(),
            updated_revenues.values().copied().collect(),
        );

        // Get the chain ID from the configured provider
        let chain_id = self.validation.provider.chain_spec().chain_id();

        // Get the chain ID from the configured provider
        let signer_address = signer.address();

        let nonce = builder.get_state().basic_ref(signer_address)?.map_or(0, |info| info.nonce) + 1;

        let disperse_tx = TxEip1559 {
            chain_id,
            nonce,
            // TODO: compute proper gas limit
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
        let is_valid = builder.append_transaction(signed_disperse_tx)?;

        if !is_valid {
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
            value: proposer_value,
            access_list: Default::default(),
            input: Default::default(),
        };

        let signed_proposer_payment_tx = sign_transaction(signer, proposer_payment_tx)?;

        let is_valid = builder.append_transaction(signed_proposer_payment_tx)?;

        if !is_valid {
            return Err(BlockMergingApiError::ProposerPaymentReverted);
        }

        Ok(())
    }
}

fn sign_transaction(signer: &PrivateKeySigner, tx: TxEip1559) -> Result<RecoveredTx, BlockMergingApiError> {
    let signature = signer.sign_hash_sync(&tx.signature_hash()).expect("signer is local and private key is valid");
    let signed_tx = tx.into_signed(signature);

    // We encode and decode the transaction to turn it into the same SignedTx type expected by the type bounds
    let mut buf = vec![];
    signed_tx.encode_2718(&mut buf);
    let signed_tx = SignedTx::decode_2718(&mut buf.as_slice()).expect("we just encoded it with encode_2718");
    let recovered_signed_tx = Recovered::new_unchecked(signed_tx, signer.address());
    Ok(recovered_signed_tx)
}

/// Encodes a call to `disperseEther(address[],uint256[])` with the given recipients and values.
pub(crate) fn encode_disperse_eth_calldata(recipients: Vec<Address>, values: Vec<U256>) -> Vec<u8> {
    sol! {
        function disperseEther(address[] recipients, uint256[] values) external payable;
    }
    disperseEtherCall { recipients, values }.abi_encode()
}

/// Computes revenue distribution, splitting merged block revenue to the multiple participants.
/// Returns the proposer value, the distributed value to other parties, and the
/// revenue to be distributed to each address.
pub(crate) fn prepare_revenues(
    distribution_config: &DistributionConfig,
    revenues: HashMap<Address, U256>,
    relay_fee_recipient: Address,
    original_block_value: U256,
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

        let builder_revenue = distribution_config.builder_split(revenue);
        updated_revenues.entry(origin).and_modify(|v| *v += builder_revenue).or_insert(builder_revenue);

        // Add both to the total value to be distributed
        distributed_value += builder_revenue + relay_revenue;

        // Add proposer revenue to the proposer added value
        proposer_added_value += distribution_config.proposer_split(revenue);
    }

    // Just in case, we remove the beneficiary address from the distribution and update the total
    distributed_value -= updated_revenues.remove(&block_beneficiary).unwrap_or(U256::ZERO);

    let proposer_value = original_block_value + proposer_added_value;

    (proposer_value, distributed_value, updated_revenues)
}

struct BlockBuilder<BB> {
    evm_config: EthEvmConfig,
    evm_env: EvmEnvFor<EthEvmConfig>,
    block_builder: BB,

    gas_used: u64,
    gas_limit: u64,
    transactions: Vec<RecoveredTx>,
    tx_hashes: HashSet<TxHash>,

    blob_versioned_hashes: Vec<B256>,
    number_of_blobs_in_base_block: usize,
}

impl<'a, BB, Ex, Ev> BlockBuilder<BB>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'a,
    Ev: Evm<DB = &'a mut CachedRethDb<'a>> + 'a,
{
    fn new(evm_config: EthEvmConfig, evm_env: EvmEnvFor<EthEvmConfig>, block_builder: BB, gas_limit: u64) -> Self {
        Self {
            evm_config,
            evm_env,
            block_builder,
            gas_used: 0,
            gas_limit,
            transactions: Default::default(),
            tx_hashes: Default::default(),
            blob_versioned_hashes: Default::default(),
            number_of_blobs_in_base_block: 0,
        }
    }

    fn execute_base_block(&mut self, txs: Vec<SignedTx>) -> Result<(), BlockExecutionError> {
        self.block_builder.apply_pre_execution_changes()?;

        self.transactions = Vec::with_capacity(txs.len());

        // Keep track of already applied txs, to discard duplicates
        self.tx_hashes = HashSet::with_capacity(txs.len());

        // Insert the transactions from the unmerged block
        for tx in txs {
            let tx: RecoveredTx = tx.try_into_recovered().expect("signature is valid");

            self.tx_hashes.insert(*tx.tx_hash());

            if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                self.number_of_blobs_in_base_block += 1;
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

        let simulated_order = simulate_order(&self.evm_config, self.get_state(), self.evm_env.clone(), order)?;
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

    fn append_transaction(&mut self, tx: RecoveredTx) -> Result<bool, BlockExecutionError> {
        let mut is_valid = false;
        self.gas_used +=
            self.block_builder.execute_transaction_with_result_closure(tx.clone(), |r| is_valid = r.is_success())?;

        self.transactions.push(tx.clone());
        self.tx_hashes.insert(*tx.tx_hash());
        // If tx has blobs, store the order index and tx sub-index to add the blobs to the payload
        // Also store the versioned hash for validation
        if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
            self.blob_versioned_hashes.extend(versioned_hashes);
        }
        Ok(is_valid)
    }

    fn finish(self, state_provider: &dyn StateProvider) -> Result<BuiltBlock, BlockMergingApiError> {
        let number_of_blobs_in_base_block = self.number_of_blobs_in_base_block;
        let blob_versioned_hashes = self.blob_versioned_hashes;

        let outcome = self.block_builder.finish(state_provider)?;
        let execution_requests =
            outcome.execution_result.requests.try_into().or(Err(BlockMergingApiError::ExecutionRequests))?;

        let blob_gas_used = outcome.block.blob_gas_used().unwrap_or(0);
        let excess_blob_gas = outcome.block.excess_blob_gas().unwrap_or(0);
        let block = outcome.block.into_block().into_ethereum_block();

        let payload_inner = ExecutionPayloadV2::from_block_slow(&block);

        let execution_payload = ExecutionPayloadV3 { payload_inner, blob_gas_used, excess_blob_gas };

        let appended_blob_versioned_hashes = blob_versioned_hashes[number_of_blobs_in_base_block..].to_vec();
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
        for (_i, tx) in order.into_transactions().into_iter().enumerate().filter(|(i, _tx)| should_be_included[*i]) {
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
    let initial_balance = evm.db().basic_ref(evm.block.beneficiary)?.map_or(U256::ZERO, |info| info.balance);

    let txs = order.transactions();
    let reverting_txs = order.reverting_txs();
    let dropping_txs = order.dropping_txs();

    let mut gas_used = 0;
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
                        return Err(SimulationError::RevertNotAllowed(i));
                    }
                }
                gas_used += result.result.gas_used();
                // Apply the state changes to the simulated state
                // Note that this only commits to the cache wrapper, not the underlying database
                evm.db_mut().commit(result.state);
            }
            Err(e) => {
                if e.is_invalid_tx_err() && (dropping_txs.contains(&i) || reverting_txs.contains(&i)) {
                    // The transaction might have been invalidated by another one, so we drop it
                    included_txs[i] = false;
                } else {
                    // The error isn't transaction-related or tx can't be dropped, so we just drop this bundle
                    return Err(SimulationError::DropNotAllowed(i));
                }
            }
        };
    }
    let final_balance = evm.db().basic_ref(evm.block.beneficiary)?.map_or(U256::ZERO, |info| info.balance);
    let builder_payment = final_balance.saturating_sub(initial_balance);
    Ok(SimulatedOrder { order, gas_used, should_be_included: included_txs, builder_payment })
}
