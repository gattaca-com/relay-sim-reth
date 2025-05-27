//! Example of how to use additional rpc namespaces in the reth CLI
//!
//! Run with
//!
//! ```sh
//! cargo run -p node-custom-rpc -- node --http --ws --enable-ext
//! ```
//!
//! This installs an additional RPC method `txpoolExt_transactionCount` that can be queried via [cast](https://github.com/foundry-rs/foundry)
//!
//! ```sh
//! cast rpc txpoolExt_transactionCount
//! ```

#![warn(unused_crate_dependencies)]

mod inclusion;
mod validation;

use std::sync::Arc;

use clap::Parser;
use inclusion::inclusion_producer;
use jsonrpsee::{
    PendingSubscriptionSink, SubscriptionMessage,
    core::{RpcResult, SubscriptionResult},
    proc_macros::rpc,
};
use reth_chain_state::ForkChoiceSubscriptions;
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::{node::EthereumAddOns, EthereumEngineValidator, EthereumNode},
    rpc::{api::{eth::RpcNodeCore}, builder::RethRpcModule, eth::error::RpcPoolError},
};
use reth_node_builder::FullNodeComponents;
use revm_primitives::Bytes;
use tokio::sync::watch::Receiver;
use validation::{ValidationApi, ValidationApiConfig};
use crate::validation::BlockSubmissionValidationApiServer;

#[tokio::main]
async fn main() {
    Cli::<EthereumChainSpecParser, InclusionListsExt>::parse()
        .run(|builder, args| async move {
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(EthereumNode::components().map_pool(|pool| {
                    // TODO set cutom order on the pool?
                    pool
                }))
                .with_add_ons(EthereumAddOns::default())
                .extend_rpc_modules(move |ctx| {
                    if !args.enable_ext {
                        return Ok(());
                    }

                    // Handle to the transaction pool.
                    let pool = ctx.pool().clone();

                    // Fork choice update stream.
                    let notifications = ctx.provider().subscribe_safe_block();

                    // List publisher
                    let (publisher, published) = tokio::sync::watch::channel(None::<Vec<Bytes>>);

                    tokio::spawn(inclusion_producer(pool, notifications, publisher));

                    let ext = InclusionExt { published };

                    // now we merge our extension namespace into all configured transports
                    ctx.modules.merge_configured(ext.into_rpc())?;

                    let validation_api = ValidationApi::new(
                        ctx.node().provider.clone(),
                        Arc::new(ctx.node().consensus().clone()),
                        RpcNodeCore::evm_config(ctx.node()).clone(),
                        ValidationApiConfig::default(),
                        Box::new(ctx.node().task_executor.clone()),
                        Arc::new(EthereumEngineValidator::new(ctx.config().chain.clone())),
                    );

                    ctx.modules.merge_configured(validation_api.into_rpc())?;

                    Ok(())
                })
                .launch()
                .await?;

            handle.wait_for_node_exit().await
        })
        .unwrap();
}

/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
struct InclusionListsExt {
    /// CLI flag to enable the txpool extension namespace
    #[arg(long)]
    pub enable_ext: bool,
}

/// trait interface for a custom rpc namespace: `inclusion`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "inclusionExt"))]
#[cfg_attr(test, rpc(server, client, namespace = "inclusionExt"))]
pub trait InclusionExtApi {
    /// Returns the current inclusion list.
    #[method(name = "inclusionList")]
    fn inclusion_list(&self) -> RpcResult<Vec<Bytes>>;

    /// Creates a subscription that returns the inclusion list when it is published.
    #[subscription(name = "subscribeInclusionList", item = usize)]
    fn subscribe_inclusion_list(&self) -> SubscriptionResult;
}

/// The type that implements the `inclusion` rpc namespace trait
pub struct InclusionExt {
    published: Receiver<Option<Vec<Bytes>>>,
}

impl InclusionExtApiServer for InclusionExt {
    fn inclusion_list(&self) -> RpcResult<Vec<Bytes>> {
        match self.published.borrow().clone() {
            Some(list) => RpcResult::Ok(list),
            None => RpcResult::Err(RpcPoolError::Other("list not ready".into()).into()),
        }
    }

    fn subscribe_inclusion_list(
        &self,
        pending_subscription_sink: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let mut published = self.published.clone();
        tokio::spawn(async move {
            let sink = match pending_subscription_sink.accept().await {
                Ok(sink) => sink,
                Err(e) => {
                    println!("failed to accept subscription: {e}");
                    return;
                }
            };

            loop {
                match published.changed().await {
                    Ok(_) => {
                        let msg = published.borrow_and_update().clone().and_then(|list| {
                            match SubscriptionMessage::new(
                                sink.method_name(),
                                sink.subscription_id(),
                                &list,
                            ) {
                                Ok(msg) => Some(msg),
                                Err(e) => {
                                    tracing::error!(error=?e, "could not serialize inclusion list");
                                    None
                                }
                            }
                        });
                        if let Some(msg) = msg {
                            let _ = sink.send(msg).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error=?e, "list publisher closed - exiting");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}
