use std::collections::HashMap;

use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use alloy_rpc_types_engine::ExecutionPayloadV3;
use bytes::Bytes;
use reth_ethereum::evm::EthEvmConfig;
use reth_node_builder::ConfigureEvm;
use reth_primitives::{NodePrimitives, Recovered};
use revm_primitives::{Address, U256, address};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

pub(crate) type SignedTx = <<EthEvmConfig as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx;
pub(crate) type RecoveredTx = Recovered<SignedTx>;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BlockMergingConfig {
    /// Builder coinbase -> collateral signer. The base block coinbase will accrue fees and disperse from its
    /// collateral address
    pub builder_collateral_map: HashMap<Address, PrivateKeySigner>,
    /// Address for the relay's share of fees
    pub relay_fee_recipient: Address,
    /// Configuration for revenue distribution.
    pub distribution_config: DistributionConfig,
    /// Address of disperse contract.
    /// It must have a `disperseEther(address[],uint256[])` function.
    pub disperse_address: Address,
    /// Whether to validate merged blocks or not
    pub validate_merged_blocks: bool,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
/// Wrapper over [`alloy_signer_local::PrivateKeySigner`], that implements [`serde::Deserialize`]
pub(crate) struct PrivateKeySigner(#[serde_as(as = "DisplayFromStr")] pub(crate) alloy_signer_local::PrivateKeySigner);

impl Default for BlockMergingConfig {
    fn default() -> Self {
        Self {
            builder_collateral_map: HashMap::new(),
            relay_fee_recipient: address!("0x0000000000000000000000000000000000000000"),
            distribution_config: DistributionConfig::default(),
            // Address of `Disperse.app` contract
            // https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150
            disperse_address: address!("0xD152f549545093347A162Dce210e7293f1452150"),
            validate_merged_blocks: true,
        }
    }
}

/// Configuration for revenue distribution among different parties.
/// The total basis points is 10000, which means each participant
/// will be paid `revenue * x / 10000`.
///
/// This config does not have an explicit proposer allocation.
/// It is assumed it will be the remaining bips not allocated
/// to other parties.
#[derive(Debug, Serialize, Eq, PartialEq, Deserialize, Clone)]
pub(crate) struct DistributionConfig {
    /// Base points allocated to the relay.
    relay_bps: u64,
    /// Base points allocated to the builder that sent the bundle.
    merged_builder_bps: u64,
    /// Base points allocated to the winning builder.
    winning_builder_bps: u64,
}

impl Default for DistributionConfig {
    fn default() -> Self {
        let relay_bps = Self::TOTAL_BPS / 4;
        let merged_builder_bps = Self::TOTAL_BPS / 4;
        let winning_builder_bps = Self::TOTAL_BPS / 4;

        Self { relay_bps, merged_builder_bps, winning_builder_bps }
    }
}

impl DistributionConfig {
    const TOTAL_BPS: u64 = 10000;

    pub(crate) fn validate(&self) {
        assert!(
            self.relay_bps + self.winning_builder_bps + self.merged_builder_bps < Self::TOTAL_BPS,
            "invalid distribution config, sum of bps exceeds 10000"
        );
    }

    pub(crate) fn split(&self, bips: u64, revenue: U256) -> U256 {
        (U256::from(bips) * revenue) / U256::from(Self::TOTAL_BPS)
    }

    pub(crate) fn relay_split(&self, revenue: U256) -> U256 {
        self.split(self.relay_bps, revenue)
    }

    pub(crate) fn proposer_split(&self, revenue: U256) -> U256 {
        let proposer_bips = Self::TOTAL_BPS - self.relay_bps - self.merged_builder_bps - self.winning_builder_bps;
        self.split(proposer_bips, revenue)
    }

    pub(crate) fn builder_split(&self, revenue: U256) -> U256 {
        self.split(self.merged_builder_bps, revenue)
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
