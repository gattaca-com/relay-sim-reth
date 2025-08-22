use std::sync::Arc;

use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use jsonrpsee::{proc_macros::rpc, types::ErrorObject};
use reth_ethereum::node::core::rpc::result::internal_rpc_err;
use revm_primitives::Address;
use tokio::sync::oneshot;

use crate::{
    block_merging::types::{BlockMergeRequestV1, BlockMergeResponseV1, BlockMergingConfig, DistributionConfig},
    validation::ValidationApi,
};

/// Block validation rpc interface.
#[rpc(server, namespace = "relay")]
pub trait BlockMergingApi {
    /// A Request to append mergeable transactions to a block.
    #[method(name = "mergeBlockV1")]
    async fn merge_block_v1(&self, request: BlockMergeRequestV1) -> jsonrpsee::core::RpcResult<BlockMergeResponseV1>;
}

/// The type that implements the block merging rpc trait
#[derive(Clone, Debug, derive_more::Deref)]
pub(crate) struct BlockMergingApi {
    #[deref]
    inner: Arc<BlockMergingApiInner>,
}

impl BlockMergingApi {
    /// Create a new instance of the [`BlockMergingApi`]
    pub fn new(validation: ValidationApi, config: BlockMergingConfig) -> Self {
        let BlockMergingConfig { .. } = config;

        let merger_signer = config.merger_private_key.parse().expect("Failed to parse merger private key");

        let inner = Arc::new(BlockMergingApiInner {
            validation,
            relay_fee_recipient: config.relay_fee_recipient,
            merger_signer,
            distribution_contract: config.distribution_contract,
            distribution_config: config.distribution_config,
            validate_merged_blocks: config.validate_merged_blocks,
        });

        Self { inner }
    }
}

pub(crate) struct BlockMergingApiInner {
    /// The validation API.
    pub(crate) validation: ValidationApi,
    /// The address to send relay revenue to.
    pub(crate) relay_fee_recipient: Address,
    /// The signer to use for merging blocks. It will be used for signing the
    /// revenue distribution and proposer payment transactions.
    pub(crate) merger_signer: PrivateKeySigner,
    /// The address of the contract used to distribute rewards.
    /// It must have a `disperseEther(address[],uint256[])` function.
    pub(crate) distribution_contract: Address,
    /// Configuration for revenue distribution.
    pub(crate) distribution_config: DistributionConfig,
    /// Whether to validate merged blocks or not
    pub(crate) validate_merged_blocks: bool,
}

impl core::fmt::Debug for BlockMergingApiInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockMergingApiInner").finish_non_exhaustive()
    }
}

#[async_trait]
impl BlockMergingApiServer for BlockMergingApi {
    /// A Request to append mergeable transactions to a block.
    async fn merge_block_v1(&self, request: BlockMergeRequestV1) -> jsonrpsee::core::RpcResult<BlockMergeResponseV1> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.validation.task_spawner.spawn_blocking(Box::pin(async move {
            let result = Self::merge_block_v1(&this, request).await.map_err(ErrorObject::from);
            let _ = tx.send(result);
        }));

        rx.await.map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }
}
