use std::collections::{BinaryHeap, HashMap, HashSet};

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
        revm::database::StateProviderDatabase,
    },
    primitives::SignedTransaction,
    provider::ChainSpecProvider,
    storage::{StateProvider, StateProviderFactory},
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
            BlockMergeRequestV1, BlockMergeResponseV1, DistributionConfig, MergeableOrder, MergeableOrderWithOrigin,
            RecoveredTx, SignedTx,
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
        info!(target: "rpc::relay", "Merging block v1");
        let validation = &self.validation;
        let evm_config = &validation.evm_config;

        let block: Block = request.execution_payload.try_into_block().map_err(NewPayloadError::Eth)?;

        let (header, body) = block.split();

        let (withdrawals, mut transactions) = (body.withdrawals, body.transactions);

        let block_base_fee_per_gas = header.base_fee_per_gas.unwrap_or_default();

        let proposer_fee_recipient = request.proposer_fee_recipient;
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
        if payment_tx.value() != request.original_value || payment_tx.to() != Some(proposer_fee_recipient) {
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

        let (response, blob_versioned_hashes, request_cache) = {
            let state_provider = validation.provider.state_by_block_hash(parent_hash)?;

            let mut request_cache = validation.cached_reads(parent_hash).await;

            let cached_db = request_cache.as_db(StateProviderDatabase::new(&state_provider));

            let mut state_db = State::builder().with_database_ref(&cached_db).build();

            let parent_header = validation.get_parent_header(parent_hash)?;

            // Execute the base block
            let evm_env = evm_config
                .next_evm_env(&parent_header, &new_block_attrs)
                .or(Err(BlockMergingApiError::NextEvmEnvFail))?;

            let evm = evm_config.evm_with_env(&mut state_db, evm_env.clone());
            let ctx = evm_config.context_for_next_block(&parent_header, new_block_attrs.clone());

            let block_builder = evm_config.create_block_builder(evm, &parent_header, ctx);

            let mut builder = BlockBuilder::new(evm_config, evm_env, block_builder, gas_limit);

            builder.execute_base_block(transactions)?;

            let scored_orders = score_orders(&mut builder, beneficiary, &request.merging_data)?;

            let revenues = append_greedily_until_gas_limit(&mut builder, beneficiary, scored_orders)?;

            let (proposer_value, distributed_value, updated_revenues) = prepare_revenues(
                &self.distribution_config,
                revenues,
                relay_fee_recipient,
                request.original_value,
                beneficiary,
            );

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
            let proposer_value = U256::ZERO;

            let response = BlockMergeResponseV1 {
                execution_payload: built_block.execution_payload,
                execution_requests: built_block.execution_requests,
                appended_blobs: built_block.appended_blob_versioned_hashes,
                proposer_value,
            };
            (response, built_block.blob_versioned_hashes, request_cache)
        };
        let block_hash = response.execution_payload.payload_inner.payload_inner.block_hash;

        self.validation.update_cached_reads(parent_hash, request_cache).await;

        if self.validate_merged_blocks {
            let gas_used = response.execution_payload.payload_inner.payload_inner.gas_used;
            let message = BidTrace {
                slot: 0, // unused
                parent_hash,
                block_hash,
                builder_pubkey: Default::default(),  // unused
                proposer_pubkey: Default::default(), // unused
                proposer_fee_recipient,
                gas_limit: new_block_attrs.gas_limit,
                gas_used,
                value: response.proposer_value,
            };
            let block = self.validation.payload_validator.ensure_well_formed_payload(ExecutionData {
                payload: ExecutionPayload::V3(response.execution_payload.clone()),
                sidecar: ExecutionPayloadSidecar::v4(
                    CancunPayloadFields {
                        parent_beacon_block_root: new_block_attrs.parent_beacon_block_root.unwrap(),
                        versioned_hashes: blob_versioned_hashes,
                    },
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(response.execution_requests.to_requests()),
                    },
                ),
            })?;

            self.validation.validate_message_against_block(block, message, 0, false, None).await?;
        }

        Ok(response)
    }

    fn append_payment_txs<'a, BB, Ex, Ev>(
        &self,
        builder: &mut BlockBuilder<'a, BB>,
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

/// Recovers transactions from a bundle
pub(crate) fn recover_transactions(
    order: &MergeableOrder,
    applied_txs: &HashSet<TxHash>,
) -> Option<Vec<(usize, RecoveredTx)>> {
    order
        .transactions()
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            let mut buf = b.as_ref();
            let Ok(tx) = <SignedTx as Decodable2718>::decode_2718(&mut buf) else {
                return Some(Err(()));
            };
            if !buf.is_empty() {
                return Some(Err(()));
            }
            // Check if it was already applied
            if !applied_txs.contains(tx.tx_hash()) {
                if order.dropping_txs().contains(&i) {
                    // If the transaction was already applied and can be dropped, we drop it
                    return None;
                } else {
                    // If it can't be dropped, we return an error
                    return Some(Err(()));
                }
            }
            let Ok(recovered) = tx.try_into_recovered() else {
                return Some(Err(()));
            };
            Some(Ok((i, recovered)))
        })
        .collect::<Result<_, _>>()
        .ok()
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

struct BlockBuilder<'a, BB> {
    evm_config: &'a EthEvmConfig,
    evm_env: EvmEnvFor<EthEvmConfig>,
    block_builder: BB,

    gas_used: u64,
    gas_limit: u64,
    transactions: Vec<RecoveredTx>,
    tx_hashes: HashSet<TxHash>,

    blob_versioned_hashes: Vec<B256>,
    number_of_blobs_in_base_block: usize,
}

impl<'a, 'b, BB, Ex, Ev> BlockBuilder<'a, BB>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'b,
    Ev: Evm<DB = &'b mut CachedRethDb<'b>> + 'b,
{
    fn new(evm_config: &'a EthEvmConfig, evm_env: EvmEnvFor<EthEvmConfig>, block_builder: BB, gas_limit: u64) -> Self {
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
            // TODO: avoid clone
            self.gas_used += self.block_builder.execute_transaction(tx.clone())?;

            self.tx_hashes.insert(*tx.tx_hash());
            if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                self.number_of_blobs_in_base_block += 1;
                self.blob_versioned_hashes.extend(versioned_hashes);
            }
        }

        Ok(())
    }

    fn get_state<'c>(&'c self) -> &'c CachedRethDb<'b> {
        self.block_builder.executor().evm().db()
    }

    fn was_already_applied(&self, tx_hash: &TxHash) -> bool {
        self.tx_hashes.contains(tx_hash)
    }

    fn simulate_order<'c>(
        &'c self,
        order: &MergeableOrder,
        txs: &[(usize, RecoveredTx)],
    ) -> SimulationResult<&'c CachedRethDb<'b>> {
        let reverting_txs = order.reverting_txs();
        let dropping_txs = order.dropping_txs();
        let mut result =
            simulate_order(self.evm_config, self.get_state(), self.evm_env.clone(), reverting_txs, dropping_txs, txs);
        // If we go past gas limit, return an invalid result
        if self.gas_used + result.gas_used > self.gas_limit {
            result.is_valid = false;
        }
        result
    }

    fn recover_transactions(&self, order: &MergeableOrder) -> Option<Vec<(usize, RecoveredTx)>> {
        recover_transactions(order, &self.tx_hashes)
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

struct SimulationResult<DB> {
    is_valid: bool,
    gas_used: u64,
    should_be_included: Vec<bool>,
    resulting_state: CacheDB<DB>,
}

impl<DB> SimulationResult<DB> {
    fn new_invalid(resulting_state: CacheDB<DB>) -> Self {
        Self { is_valid: false, gas_used: 0, should_be_included: vec![], resulting_state }
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

/// Keeps a list of recovered transactions per bundle, and an index by score
struct ScoredOrders<'a> {
    original_orders: &'a [MergeableOrderWithOrigin],
    scored_orders: Vec<(usize, Vec<(usize, RecoveredTx)>)>,
    orders_by_score: BinaryHeap<(U256, usize)>,
}

impl<'a> ScoredOrders<'a> {
    /// Creates an ordered index for `original_orders` using the `scorer` function.
    /// The scoring function receives a reference to an order and may return a
    /// score and a list of recovered transactions, or [`None`] if the order should
    /// be discarded.
    fn from_orders_with_scorer<F, Error>(
        original_orders: &'a [MergeableOrderWithOrigin],
        scorer: F,
    ) -> Result<Self, Error>
    where
        F: Fn(&MergeableOrderWithOrigin) -> Result<Option<(U256, Vec<(usize, RecoveredTx)>)>, Error>,
    {
        let mut scored_orders = Vec::with_capacity(original_orders.len());
        let mut orders_by_score = BinaryHeap::with_capacity(original_orders.len());
        for (i, order) in original_orders.iter().enumerate() {
            if let Some((score, recovered_txs)) = scorer(order)? {
                orders_by_score.push((score, scored_orders.len()));
                scored_orders.push((i, recovered_txs));
            }
        }
        Ok(Self { original_orders, scored_orders, orders_by_score })
    }

    /// Returns an iterator over the scored orders by score, in descending order.
    fn iter_by_score(mut self) -> impl Iterator<Item = ScoredOrder<'a>> {
        std::iter::from_fn(move || {
            let (_score, scored_orders_index) = self.orders_by_score.pop()?;
            // NOTE: this `take` won't cause problems because indices to this array are
            // unique across the score index
            let (original_index, txs) = std::mem::take(&mut self.scored_orders[scored_orders_index]);
            let mergeable_order = &self.original_orders[original_index];
            Some(ScoredOrder { original_index, mergeable_order, recovered_txs: txs })
        })
    }
}

struct ScoredOrder<'a> {
    original_index: usize,
    mergeable_order: &'a MergeableOrderWithOrigin,
    recovered_txs: Vec<(usize, RecoveredTx)>,
}

fn score_orders<'a, 'b, 'c, BB, Ex, Ev>(
    builder: &mut BlockBuilder<'a, BB>,
    beneficiary: Address,
    mergeable_orders: &'c [MergeableOrderWithOrigin],
) -> Result<ScoredOrders<'c>, BlockMergingApiError>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'b,
    Ev: Evm<DB = &'b mut CachedRethDb<'b>> + 'b,
{
    let initial_balance = builder.get_state().basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

    ScoredOrders::from_orders_with_scorer(mergeable_orders, |order_with_origin| -> Result<_, BlockMergingApiError> {
        let order = &order_with_origin.order;
        // The mergeable transactions should come from already validated payloads
        // But in case decoding fails, we just skip the bundle
        let Some(txs) = builder.recover_transactions(order) else {
            return Ok(None);
        };

        let simulation_result = builder.simulate_order(order, &txs);
        let bundle_is_valid = simulation_result.is_valid;
        let cached_db = simulation_result.resulting_state;

        if !bundle_is_valid {
            return Ok(None);
        }

        // Consider any balance changes on the beneficiary as tx value
        let new_balance = cached_db.basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

        let total_value = new_balance.saturating_sub(initial_balance);

        // If the total value is zero, discard the bundle
        if total_value.is_zero() {
            return Ok(None);
        }
        // Use the tx's value as its score
        // We could use other heuristics here
        let score = total_value;
        Ok(Some((score, txs)))
    })
}

fn append_greedily_until_gas_limit<'a, 'b, 'c, BB, Ex, Ev>(
    builder: &mut BlockBuilder<'a, BB>,
    beneficiary: Address,
    scored_orders: ScoredOrders<'c>,
) -> Result<HashMap<Address, U256>, BlockMergingApiError>
where
    BB: RethBlockBuilder<Primitives = EthPrimitives, Executor = Ex>,
    Ex: BlockExecutor<Transaction = SignedTx, Evm = Ev> + 'b,
    Ev: Evm<DB = &'b mut CachedRethDb<'b>> + 'b,
{
    let mut revenues = HashMap::new();

    let mut current_balance = builder.get_state().basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

    // Append transactions by score until we run out of space
    for scored_order in scored_orders.iter_by_score() {
        let order = &scored_order.mergeable_order.order;
        let origin = scored_order.mergeable_order.origin;
        let dropping_txs = order.dropping_txs();

        // Check for already applied transactions and try to drop them
        let filtered_txs = scored_order
            .recovered_txs
            .into_iter()
            .filter_map(|(i, tx)| {
                if !builder.was_already_applied(tx.tx_hash()) {
                    Some(Ok((i, tx)))
                } else if dropping_txs.contains(&i) {
                    None
                } else {
                    Some(Err(()))
                }
            })
            .collect::<Result<Vec<_>, _>>();

        // Discard the bundle if any duplicates couldn't be dropped
        let Ok(txs) = filtered_txs else {
            continue;
        };

        let result = builder.simulate_order(order, &txs);

        let bundle_is_valid = result.is_valid;
        let should_be_included = result.should_be_included;

        if !bundle_is_valid {
            continue;
        }

        // Execute the transaction bundle

        let mut total_value = U256::ZERO;

        for (_i, tx) in txs.into_iter().filter(|(i, _tx)| should_be_included[*i]) {
            builder.append_transaction(tx)?;
        }
        // Consider any balance changes on the beneficiary as tx value
        let new_balance = builder.get_state().basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

        total_value += new_balance.saturating_sub(current_balance);
        current_balance = new_balance;

        // Update the revenue for the bundle's origin
        if !total_value.is_zero() {
            revenues.entry(origin).and_modify(|v| *v += total_value).or_insert(total_value);
        }
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
    reverting_txs: &[usize],
    dropping_txs: &[usize],
    txs: &[(usize, RecoveredTx)],
) -> SimulationResult<DBRef>
where
    DBRef: DatabaseRef + core::fmt::Debug,
    DBRef::Error: Send + Sync + 'static,
{
    // Wrap current state in cache to avoid mutating it
    let cached_db = CacheDB::new(db_ref);
    // Create a new EVM with the pre-state
    let mut evm = evm_config.evm_with_env(cached_db, evm_env);

    let mut gas_used_in_bundle = 0;
    let mut included_txs = vec![true; txs.last().map(|(i, _)| *i + 1).unwrap_or(0)];

    // Check the bundle can be included in the block
    for (i, tx) in txs {
        let i = *i;
        match evm.transact(tx) {
            Ok(result) => {
                // If tx reverted and is not allowed to
                if !result.result.is_success() && !reverting_txs.contains(&i) {
                    // We check if we can drop it instead, else we discard this bundle
                    if dropping_txs.contains(&i) {
                        // Tx should be dropped
                        included_txs[i] = false;
                    } else {
                        return SimulationResult::new_invalid(evm.into_db());
                    }
                }
                gas_used_in_bundle += result.result.gas_used();
                // Apply the state changes to the simulated state
                // Note that this only commits to the cache wrapper, not the underlying database
                evm.db_mut().commit(result.state);
            }
            Err(e) => {
                if e.is_invalid_tx_err() && (dropping_txs.contains(&i) || reverting_txs.contains(&i)) {
                    // The transaction might have been invalidated by another one, so we drop it
                    included_txs[i] = false;
                } else {
                    // The error isn't transaction-related, so we just drop this bundle
                    return SimulationResult::new_invalid(evm.into_db());
                }
            }
        };
    }
    SimulationResult {
        is_valid: true,
        gas_used: gas_used_in_bundle,
        should_be_included: included_txs,
        resulting_state: evm.into_db(),
    }
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
        let actual = encode_disperse_eth_calldata(
            input.iter().map(|(a, _)| *a).collect(),
            input.iter().map(|(_, v)| *v).collect(),
        );
        assert_eq!(actual, expected);
    }
}
