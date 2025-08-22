use std::collections::{BinaryHeap, HashMap, HashSet};

use alloy_consensus::{
    BlockHeader, EMPTY_OMMER_ROOT_HASH, Header, SignableTransaction, Transaction, TxEip1559, TxReceipt,
    proofs::{self, ordered_trie_root_with_encoder},
};
use alloy_eips::{
    Decodable2718, Encodable2718,
    eip4895::Withdrawals,
    eip7685::{Requests, RequestsOrHash},
    merge::BEACON_NONCE,
};
use alloy_rpc_types_beacon::{relay::BidTrace, requests::ExecutionRequestsV4};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV2,
    ExecutionPayloadV3, PraguePayloadFields,
};
use alloy_signer::SignerSync;
use reth_ethereum::{
    Block, BlockBody,
    chainspec::EthChainSpec as _,
    evm::{
        EthEvmConfig,
        primitives::{
            Evm, EvmEnvFor, EvmError,
            block::{BlockExecutionError, BlockExecutor as _, BlockExecutorFor},
            execute::ExecutorTx,
        },
        revm::database::StateProviderDatabase,
    },
    primitives::SignedTransaction,
    provider::ChainSpecProvider,
    storage::{StateProvider, StateProviderFactory},
};
use reth_node_builder::{Block as _, ConfigureEvm, NewPayloadError, NextBlockEnvAttributes, PayloadValidator};
use reth_primitives::{EthereumHardforks, NodePrimitives, Recovered, RecoveredBlock, logs_bloom};
use revm::{
    Database, DatabaseCommit, DatabaseRef,
    database::{CacheDB, State, states::bundle_state::BundleRetention},
};
use revm_primitives::{Address, B256, U256, alloy_primitives::TxHash};
use tracing::info;

pub(crate) use crate::block_merging::api::{BlockMergingApi, BlockMergingApiServer};
use crate::block_merging::{
    error::BlockMergingApiError,
    types::{
        BlockMergeRequestV1, BlockMergeResponseV1, DistributionConfig, MergeableOrder, MergeableOrderWithOrigin,
        RecoveredBlockFor, RecoveredTx, SignedTx,
    },
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

        let (response, block_hash, blob_versioned_hashes, request_cache) = {
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
            let mut block_executor = evm_config.create_executor(evm, ctx);

            block_executor.apply_pre_execution_changes()?;

            let mut gas_used = 0;

            let mut all_transactions = Vec::with_capacity(transactions.len());

            // Keep track of already applied txs, to discard duplicates
            let mut applied_txs = HashSet::with_capacity(transactions.len());

            // Keep track of appended orders with blobs
            let mut appended_blob_order_indices = vec![];
            let mut blob_versioned_hashes = vec![];

            // Insert the transactions from the unmerged block
            for tx in transactions {
                let tx = tx.try_into_recovered().expect("signature is valid");
                gas_used += block_executor.execute_transaction(tx.as_executable())?;

                all_transactions.push(tx.clone());
                applied_txs.insert(*tx.tx_hash());
                if let Some(versioned_hashes) = tx.blob_versioned_hashes() {
                    blob_versioned_hashes.extend(versioned_hashes);
                }
            }

            // We use a read-only reference to the State<DB> as a Database.
            // When simulating, we're going to wrap this with an in-memory DB.
            let end_of_block_state = &**block_executor.evm_mut().db_mut();

            let (txs_by_score, mergeable_transactions) = score_orders(
                evm_config,
                end_of_block_state,
                beneficiary,
                &request.merging_data,
                evm_env.clone(),
                &applied_txs,
                gas_limit,
                gas_used,
            )?;

            let revenues = append_greedily_until_gas_limit(
                evm_config,
                &mut block_executor,
                beneficiary,
                evm_env.clone(),
                txs_by_score,
                mergeable_transactions,
                &request.merging_data,
                applied_txs,
                gas_limit,
                &mut gas_used,
                &mut all_transactions,
                &mut appended_blob_order_indices,
                &mut blob_versioned_hashes,
            )?;

            let (proposer_value, distributed_value, updated_revenues) = prepare_revenues(
                &self.distribution_config,
                revenues,
                relay_fee_recipient,
                request.original_value,
                beneficiary,
            );

            let calldata = encode_disperse_eth_calldata(&updated_revenues);

            // Get the chain ID from the configured provider
            let chain_id = self.validation.provider.chain_spec().chain_id();

            let nonce = block_executor.evm_mut().db_mut().basic(beneficiary)?.map_or(0, |info| info.nonce) + 1;

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

            let signed_disperse_tx_arr = [(0, self.sign_transaction(disperse_tx)?)];

            let db = block_executor.evm_mut().db_mut();
            let (is_valid, _, _, _) =
                simulate_order(evm_config, db, evm_env.clone(), &[], &[], &signed_disperse_tx_arr);
            if !is_valid {
                return Err(BlockMergingApiError::RevenueAllocationReverted);
            }

            let [(_, signed_disperse_tx)] = signed_disperse_tx_arr;
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

            let signed_proposer_payment_tx_arr = [(0, self.sign_transaction(proposer_payment_tx)?)];

            let db = block_executor.evm_mut().db_mut();
            let (is_valid, _, _, _) =
                simulate_order(evm_config, db, evm_env.clone(), &[], &[], &signed_proposer_payment_tx_arr);
            if !is_valid {
                return Err(BlockMergingApiError::ProposerPaymentReverted);
            }

            let [(_, signed_proposer_payment_tx)] = signed_proposer_payment_tx_arr;

            all_transactions.push(signed_proposer_payment_tx);

            let (new_block, requests) = self.assemble_block(
                block_executor,
                &state_provider,
                all_transactions,
                new_block_attrs.withdrawals,
                parent_header,
                header,
            )?;

            let blob_gas_used = new_block.blob_gas_used.unwrap_or(0);
            let excess_blob_gas = new_block.excess_blob_gas.unwrap_or(0);
            let block = new_block.into_block().into_ethereum_block();

            let payload_inner = ExecutionPayloadV2::from_block_slow(&block);

            let block_hash = payload_inner.payload_inner.block_hash;

            let execution_payload = ExecutionPayloadV3 { payload_inner, blob_gas_used, excess_blob_gas };
            let execution_requests: ExecutionRequestsV4 =
                requests.try_into().or(Err(BlockMergingApiError::ExecutionRequests))?;

            let response = BlockMergeResponseV1 {
                execution_payload,
                execution_requests,
                appended_blob_order_indices,
                proposer_value,
            };
            (response, block_hash, blob_versioned_hashes, request_cache)
        };

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

    fn sign_transaction(&self, tx: TxEip1559) -> Result<Recovered<SignedTx<EthEvmConfig>>, BlockMergingApiError> {
        let signature =
            self.merger_signer.sign_hash_sync(&tx.signature_hash()).expect("signer is local and private key is valid");
        let signed_tx = tx.into_signed(signature);

        // We encode and decode the transaction to turn it into the same SignedTx type expected by the type bounds
        let mut buf = vec![];
        signed_tx.encode_2718(&mut buf);
        let signed_tx =
            SignedTx::<EthEvmConfig>::decode_2718(&mut buf.as_slice()).expect("we just encoded it with encode_2718");
        let recovered_signed_tx = Recovered::new_unchecked(signed_tx, self.merger_signer.address());
        Ok(recovered_signed_tx)
    }

    fn assemble_block<'a, DB>(
        &self,
        block_executor: impl BlockExecutorFor<'a, <EthEvmConfig as ConfigureEvm>::BlockExecutorFactory, DB>,
        state_provider: &dyn StateProvider,
        recovered_txs: Vec<RecoveredTx<EthEvmConfig>>,
        withdrawals_opt: Option<Withdrawals>,
        parent_header: reth_primitives::SealedHeader<
            <<EthEvmConfig as ConfigureEvm>::Primitives as NodePrimitives>::BlockHeader,
        >,
        old_header: Header,
    ) -> Result<(RecoveredBlockFor<EthEvmConfig>, Requests), BlockMergingApiError>
    where
        DB: Database + core::fmt::Debug + 'a,
        DB::Error: Send + Sync + 'static,
    {
        let chain_spec = self.validation.provider.chain_spec();

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
        let (state_root, _trie_updates) =
            state_provider.state_root_with_updates(hashed_state.clone()).map_err(BlockExecutionError::other)?;

        let (transactions, senders): (Vec<_>, Vec<_>) = recovered_txs.into_iter().map(|tx| tx.into_parts()).unzip();

        // Taken from `reth_evm_ethereum::build::EthBlockAssembler::assemble_block()`.
        // The function receives an unbuildable `BlockAssemblerInput`, due to being
        // marked as non-exhaustive and having no constructors.
        let timestamp = evm_env.block_env.timestamp.saturating_to();

        let transactions_root = proofs::calculate_transaction_root(&transactions);

        // Had to inline this manually due to generics
        // let receipts_root = Receipt::calculate_receipt_root_no_memo(result.receipts);
        let receipts_root =
            ordered_trie_root_with_encoder(&result.receipts, |r, buf| r.with_bloom_ref().encode_2718(buf));
        let logs_bloom = logs_bloom(result.receipts.iter().flat_map(|r| r.logs()));

        let withdrawals =
            chain_spec.is_shanghai_active_at_timestamp(timestamp).then(|| withdrawals_opt.unwrap_or_default());

        let withdrawals_root = withdrawals.as_deref().map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash =
            chain_spec.is_prague_active_at_timestamp(timestamp).then(|| result.requests.requests_hash());

        let mut excess_blob_gas = None;
        let mut blob_gas_used = None;

        // only determine cancun fields when active
        if chain_spec.is_cancun_active_at_timestamp(timestamp) {
            blob_gas_used = Some(transactions.iter().map(|tx| tx.blob_gas_used().unwrap_or_default()).sum());
            excess_blob_gas = if chain_spec.is_cancun_active_at_timestamp(parent_header.timestamp()) {
                parent_header.maybe_next_block_excess_blob_gas(chain_spec.blob_params_at_timestamp(timestamp))
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

        let block = Block { header, body: BlockBody { transactions, ommers: Default::default(), withdrawals } };

        // Continuation from `BasicBlockBuilder::finish`
        Ok((RecoveredBlock::new_unhashed(block, senders), result.requests))
    }
}

/// Recovers transactions from a bundle
pub(crate) fn recover_transactions(
    order: &MergeableOrder,
    applied_txs: &HashSet<TxHash>,
) -> Option<Vec<(usize, RecoveredTx<EthEvmConfig>)>> {
    order
        .transactions()
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            let mut buf = b.as_ref();
            let Ok(tx) = <SignedTx<EthEvmConfig> as Decodable2718>::decode_2718(&mut buf) else {
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

pub(crate) fn score_orders<DBRef>(
    evm_config: &EthEvmConfig,
    end_of_block_state: &DBRef,
    beneficiary: Address,
    mergeable_orders: &[MergeableOrderWithOrigin],
    evm_env: EvmEnvFor<EthEvmConfig>,
    applied_txs: &HashSet<TxHash>,
    gas_limit: u64,
    gas_used: u64,
) -> Result<
    (BinaryHeap<(U256, usize)>, Vec<(Address, usize, Vec<(usize, RecoveredTx<EthEvmConfig>)>)>),
    BlockMergingApiError,
>
where
    DBRef: DatabaseRef + core::fmt::Debug,
    DBRef::Error: Send + Sync + 'static,
    BlockMergingApiError: From<DBRef::Error>,
{
    let initial_balance = end_of_block_state.basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

    // Keep a list of valid transactions and an index by score
    let mut mergeable_transactions = Vec::with_capacity(mergeable_orders.len());
    let mut txs_by_score = BinaryHeap::with_capacity(mergeable_transactions.len());

    // Simulate orders, ordering them by expected value, discarding invalid ones
    for (original_index, (origin, order)) in mergeable_orders.iter().map(|mb| (mb.origin, &mb.order)).enumerate() {
        let Some(txs) = recover_transactions(order, applied_txs) else {
            // The mergeable transactions should come from already validated payloads
            // But in case decoding fails, we just skip the bundle
            continue;
        };

        let reverting_txs = order.reverting_txs();
        let dropping_txs = order.dropping_txs();

        let (bundle_is_valid, gas_used_in_bundle, _, cached_db) =
            simulate_order(evm_config, end_of_block_state, evm_env.clone(), reverting_txs, dropping_txs, &txs);

        if !bundle_is_valid || gas_used + gas_used_in_bundle > gas_limit {
            continue;
        }

        // Consider any balance changes on the beneficiary as tx value
        let new_balance = cached_db.basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

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

pub(crate) fn append_greedily_until_gas_limit<'a, DB>(
    evm_config: &EthEvmConfig,
    block_executor: &mut impl BlockExecutorFor<'a, <EthEvmConfig as ConfigureEvm>::BlockExecutorFactory, DB>,
    beneficiary: Address,
    evm_env: EvmEnvFor<EthEvmConfig>,
    mut txs_by_score: BinaryHeap<(U256, usize)>,
    mut mergeable_transactions: Vec<(Address, usize, Vec<(usize, RecoveredTx<EthEvmConfig>)>)>,
    merging_data: &[MergeableOrderWithOrigin],
    mut applied_txs: HashSet<TxHash>,
    gas_limit: u64,
    gas_used: &mut u64,
    all_transactions: &mut Vec<RecoveredTx<EthEvmConfig>>,
    appended_blob_order_indices: &mut Vec<(usize, usize)>,
    blob_versioned_hashes: &mut Vec<B256>,
) -> Result<HashMap<Address, U256>, BlockMergingApiError>
where
    DB: Database + DatabaseRef + std::fmt::Debug + 'a,
    <DB as Database>::Error: Send + Sync + 'static,
    <DB as DatabaseRef>::Error: Send + Sync + 'static,
    BlockMergingApiError: From<<DB as DatabaseRef>::Error> + From<<DB as Database>::Error>,
{
    let mut revenues = HashMap::new();

    let mut current_balance =
        block_executor.evm_mut().db_mut().basic_ref(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

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

        let (bundle_is_valid, gas_used_in_bundle, should_be_included, _) =
            simulate_order(evm_config, db, evm_env.clone(), reverting_txs, dropping_txs, &txs);

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
        let new_balance = block_executor.evm_mut().db_mut().basic(beneficiary)?.map_or(U256::ZERO, |info| info.balance);

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
pub(crate) fn simulate_order<DBRef>(
    evm_config: &EthEvmConfig,
    db_ref: DBRef,
    evm_env: EvmEnvFor<EthEvmConfig>,
    reverting_txs: &[usize],
    dropping_txs: &[usize],
    txs: &[(usize, Recovered<SignedTx<EthEvmConfig>>)],
) -> (bool, u64, Vec<bool>, CacheDB<DBRef>)
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
                        return (false, 0, vec![], evm.into_db());
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
