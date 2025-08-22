use alloy_consensus::Block;
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use alloy_rpc_types_engine::ExecutionPayloadV3;
use bytes::Bytes;
use reth_ethereum::primitives::RecoveredBlock;
use reth_node_builder::ConfigureEvm;
use reth_primitives::{NodePrimitives, Recovered};
use revm_primitives::{Address, U256, address};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub(crate) type SignedTx<E> = <<E as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx;
pub(crate) type RecoveredBlockFor<E> = RecoveredBlock<Block<SignedTx<E>>>;
pub(crate) type RecoveredTx<E> = Recovered<SignedTx<E>>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct BlockMergingConfig {
    /// Private key to use for merging blocks.
    /// The address of this key will be used for signing the revenue
    /// distribution and proposer payment transactions.
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

impl Default for BlockMergingConfig {
    fn default() -> Self {
        Self {
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
    pub(crate) fn split(&self, bips: u64, revenue: U256) -> U256 {
        (U256::from(bips) * revenue) / U256::from(self.total_bips)
    }

    pub(crate) fn relay_split(&self, revenue: U256) -> U256 {
        self.split(self.relay_bips, revenue)
    }

    pub(crate) fn proposer_split(&self, revenue: U256) -> U256 {
        self.split(self.proposer_bips, revenue)
    }

    pub(crate) fn builder_split(&self, revenue: U256) -> U256 {
        self.split(self.builder_bips, revenue)
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

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockMergeRequestV1 {
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
pub struct BlockMergeResponseV1 {
    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
    pub execution_payload: ExecutionPayloadV3,
    pub execution_requests: ExecutionRequestsV4,
    /// Indices for orders that contains blobs.
    /// The second value is the index of the tx inside the bundle.
    pub appended_blob_order_indices: Vec<(usize, usize)>,
    /// Total value for the proposer
    pub proposer_value: U256,
}
