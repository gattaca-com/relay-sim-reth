use std::sync::Arc;

use reth_ethereum::{
    EthPrimitives,
    consensus::{ConsensusError, FullConsensus},
    node::EthereumNode,
    provider::{db::DatabaseEnv, providers::BlockchainProvider},
};
use reth_node_builder::NodeTypesWithDBAdapter;

pub type RethProvider = BlockchainProvider<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>;
// can we get more concrete?
pub type RethConsensus = dyn FullConsensus<EthPrimitives, Error = ConsensusError>;
