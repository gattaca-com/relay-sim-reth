use alloy_consensus::{Block, Transaction};
use alloy_eips::Decodable2718;
use bytes::Bytes;
use reth_ethereum::evm::primitives::block::BlockExecutorFor;
use reth_ethereum::evm::primitives::execute::ExecutorTx;
use reth_ethereum::evm::primitives::{EvmEnvFor, EvmError};

use reth_ethereum::{
    evm::primitives::Evm,
    primitives::{RecoveredBlock, SignedTransaction},
};
use reth_node_builder::{ConfigureEvm, NodePrimitives};
use reth_primitives::Recovered;
use revm::Database;
use revm::database::CacheDB;
use revm::{DatabaseCommit, DatabaseRef};
use revm_primitives::alloy_primitives::TxHash;
use revm_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::{BinaryHeap, HashMap};

use crate::validation::ValidationApiError;

pub(crate) type SignedTx<E> = <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx;
pub(crate) type RecoveredBlockFor<E> = RecoveredBlock<Block<SignedTx<E>>>;
pub(crate) type RecoveredTx<E> = Recovered<SignedTx<E>>;

/// Represents one or more transactions to be appended into a block atomically.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum MergeableOrder {
    Tx(MergeableTransaction),
    Bundle(MergeableBundle),
}

impl MergeableOrder {
    pub(crate) fn transactions(&self) -> &[Bytes] {
        match self {
            MergeableOrder::Tx(tx) => std::slice::from_ref(&tx.transaction),
            MergeableOrder::Bundle(bundle) => &bundle.transactions,
        }
    }

    pub(crate) fn reverting_txs(&self) -> &[usize] {
        match self {
            MergeableOrder::Tx(tx) if tx.can_revert => &[0],
            MergeableOrder::Tx(_) => &[],
            MergeableOrder::Bundle(bundle) => &bundle.reverting_txs,
        }
    }

    pub(crate) fn dropping_txs(&self) -> &[usize] {
        match self {
            MergeableOrder::Tx(_) => &[],
            MergeableOrder::Bundle(bundle) => &bundle.dropping_txs,
        }
    }
}

/// Represents a single transaction to be appended into a block atomically.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct MergeableTransaction {
    /// Transaction that can be merged into the block.
    pub transaction: Bytes,
    /// Txs that may revert.
    pub can_revert: bool,
}

/// Represents a bundle of transactions to be appended into a block atomically.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub(crate) struct MergeableBundle {
    /// List of transactions that can be merged into the block.
    pub transactions: Vec<Bytes>,
    /// Txs that may revert.
    pub reverting_txs: Vec<usize>,
    /// Txs that are allowed to be omitted, but not revert.
    pub dropping_txs: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct MergeableOrderWithOrigin {
    /// Address of the builder that submitted this order.
    pub origin: Address,
    /// Mergeable order.
    pub order: MergeableOrder,
}

/// Recovers transactions from a bundle
pub(crate) fn recover_transactions<E>(
    order: &MergeableOrder,
    applied_txs: &HashSet<TxHash>,
) -> Option<Vec<(usize, RecoveredTx<E>)>>
where
    E: ConfigureEvm,
{
    order
        .transactions()
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            let mut buf = b.as_ref();
            let Ok(tx) = <SignedTx<E> as Decodable2718>::decode_2718(&mut buf) else {
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
pub(crate) fn encode_disperse_eth_calldata<'a, I, It>(input: I) -> Vec<u8>
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
pub(crate) struct DistributionConfig {
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
        updated_revenues
            .entry(relay_fee_recipient)
            .and_modify(|v| *v += relay_revenue)
            .or_insert(relay_revenue);

        let builder_revenue = distribution_config.builder_split(revenue);
        updated_revenues
            .entry(origin)
            .and_modify(|v| *v += builder_revenue)
            .or_insert(builder_revenue);

        // Add both to the total value to be distributed
        distributed_value += builder_revenue + relay_revenue;

        // Add proposer revenue to the proposer added value
        proposer_added_value += distribution_config.proposer_split(revenue);
    }

    // Just in case, we remove the beneficiary address from the distribution and update the total
    distributed_value -= updated_revenues
        .remove(&block_beneficiary)
        .unwrap_or(U256::ZERO);

    let proposer_value = original_block_value + proposer_added_value;

    (proposer_value, distributed_value, updated_revenues)
}

pub(crate) fn score_orders<E, DBRef>(
    evm_config: &E,
    end_of_block_state: &DBRef,
    beneficiary: Address,
    mergeable_orders: &[MergeableOrderWithOrigin],
    evm_env: EvmEnvFor<E>,
    applied_txs: &HashSet<TxHash>,
    gas_limit: u64,
    gas_used: u64,
) -> Result<
    (
        BinaryHeap<(U256, usize)>,
        Vec<(Address, usize, Vec<(usize, RecoveredTx<E>)>)>,
    ),
    ValidationApiError,
>
where
    E: ConfigureEvm,
    DBRef: DatabaseRef + core::fmt::Debug,
    DBRef::Error: Send + Sync + 'static,
    ValidationApiError: From<DBRef::Error>,
{
    let initial_balance = end_of_block_state
        .basic_ref(beneficiary)?
        .map_or(U256::ZERO, |info| info.balance);

    // Keep a list of valid transactions and an index by score
    let mut mergeable_transactions = Vec::with_capacity(mergeable_orders.len());
    let mut txs_by_score = BinaryHeap::with_capacity(mergeable_transactions.len());

    // Simulate orders, ordering them by expected value, discarding invalid ones
    for (original_index, (origin, order)) in mergeable_orders
        .iter()
        .map(|mb| (mb.origin, &mb.order))
        .enumerate()
    {
        let Some(txs) = recover_transactions::<E>(order, applied_txs) else {
            // The mergeable transactions should come from already validated payloads
            // But in case decoding fails, we just skip the bundle
            continue;
        };

        let reverting_txs = order.reverting_txs();
        let dropping_txs = order.dropping_txs();

        let (bundle_is_valid, gas_used_in_bundle, _, cached_db) = simulate_order(
            &evm_config,
            end_of_block_state,
            evm_env.clone(),
            reverting_txs,
            dropping_txs,
            &txs,
        );

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
    Ok((txs_by_score, mergeable_transactions))
}

pub(crate) fn append_greedily_until_gas_limit<'a, E, DB>(
    evm_config: &E,
    block_executor: &mut impl BlockExecutorFor<'a, <E as ConfigureEvm>::BlockExecutorFactory, DB>,
    beneficiary: Address,
    evm_env: EvmEnvFor<E>,
    mut txs_by_score: BinaryHeap<(U256, usize)>,
    mut mergeable_transactions: Vec<(Address, usize, Vec<(usize, RecoveredTx<E>)>)>,
    merging_data: &[MergeableOrderWithOrigin],
    mut applied_txs: HashSet<TxHash>,
    gas_limit: u64,
    gas_used: &mut u64,
    all_transactions: &mut Vec<RecoveredTx<E>>,
    appended_blob_order_indices: &mut Vec<(usize, usize)>,
    blob_versioned_hashes: &mut Vec<B256>,
) -> Result<HashMap<Address, U256>, ValidationApiError>
where
    E: ConfigureEvm,
    DB: Database + DatabaseRef + std::fmt::Debug + 'a,
    <DB as Database>::Error: Send + Sync + 'static,
    <DB as DatabaseRef>::Error: Send + Sync + 'static,
    ValidationApiError: From<<DB as DatabaseRef>::Error> + From<<DB as Database>::Error>,
{
    let mut revenues = HashMap::new();

    let mut current_balance = block_executor
        .evm_mut()
        .db_mut()
        .basic_ref(beneficiary)?
        .map_or(U256::ZERO, |info| info.balance);

    // Append transactions by score until we run out of space
    while let Some((_score, i)) = txs_by_score.pop() {
        let (origin, original_index, txs) = std::mem::take(&mut mergeable_transactions[i]);
        let order = &merging_data[original_index].order;
        let reverting_txs = order.reverting_txs();
        let dropping_txs = order.dropping_txs();

        // Check for already applied transactions and try to drop them
        let filtered_txs = txs
            .into_iter()
            .filter_map(|(i, tx)| {
                if !applied_txs.contains(tx.tx_hash()) {
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

        let db = block_executor.evm_mut().db_mut();

        let (bundle_is_valid, gas_used_in_bundle, should_be_included, _) = simulate_order(
            &evm_config,
            db,
            evm_env.clone(),
            reverting_txs,
            dropping_txs,
            &txs,
        );

        if !bundle_is_valid || *gas_used + gas_used_in_bundle > gas_limit {
            continue;
        }

        // Execute the transaction bundle

        let mut total_value = U256::ZERO;

        for (i, tx) in txs.into_iter() {
            if !should_be_included[i] {
                continue;
            }
            *gas_used += block_executor.execute_transaction(tx.as_executable())?;

            all_transactions.push(tx.clone());
            applied_txs.insert(*tx.tx_hash());
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
    Ok(revenues)
}

/// Simulates an order.
/// Returns whether the order is valid, the amount of gas used, and a list
/// marking whether to include a transaction of the order or not.
pub(crate) fn simulate_order<E, DBRef>(
    evm_config: &E,
    db_ref: DBRef,
    evm_env: EvmEnvFor<E>,
    reverting_txs: &[usize],
    dropping_txs: &[usize],
    txs: &[(usize, RecoveredTx<E>)],
) -> (bool, u64, Vec<bool>, CacheDB<DBRef>)
where
    E: ConfigureEvm,
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
                        return (false, 0, vec![], evm.into_db());
                    }
                }
                gas_used_in_bundle += result.result.gas_used();
                // Apply the state changes to the simulated state
                // Note that this only commits to the cache wrapper, not the underlying database
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
