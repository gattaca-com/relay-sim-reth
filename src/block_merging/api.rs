use async_trait::async_trait;
use jsonrpsee::{proc_macros::rpc, types::ErrorObject};
use reth_ethereum::{
    node::core::rpc::result::internal_rpc_err,
    provider::ChainSpecProvider,
    storage::{BlockReaderIdExt, StateProviderFactory},
};
use reth_node_builder::ConfigureEvm;
use reth_primitives::{EthereumHardforks, NodePrimitives};
use tokio::sync::oneshot;

use crate::block_merging::types::{BlockMergeRequestV1, BlockMergeResponseV1};
use crate::validation::ValidationApi;

/// Block validation rpc interface.
#[rpc(server, namespace = "relay")]
pub trait BlockMergingApi {
    /// A Request to append mergeable transactions to a block.
    #[method(name = "mergeBlockV1")]
    async fn merge_block_v1(
        &self,
        request: BlockMergeRequestV1,
    ) -> jsonrpsee::core::RpcResult<BlockMergeResponseV1>;
}

#[async_trait]
impl<Provider, E> BlockMergingApiServer for ValidationApi<Provider, E>
where
    Provider: BlockReaderIdExt<Header = <E::Primitives as NodePrimitives>::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + StateProviderFactory
        + Clone
        + 'static,
    E: ConfigureEvm + 'static,
{
    /// A Request to append mergeable transactions to a block.
    async fn merge_block_v1(
        &self,
        request: BlockMergeRequestV1,
    ) -> jsonrpsee::core::RpcResult<BlockMergeResponseV1> {
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
