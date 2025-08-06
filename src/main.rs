#![warn(unused_crate_dependencies)]

mod inclusion;
mod state_recorder;
mod validation;

use std::sync::Arc;

use crate::{
    state_recorder::run_block_state_recorder, validation::BlockSubmissionValidationApiServer,
};
use clap::Parser;
use inclusion::inclusion_producer;
use jsonrpsee::{
    PendingSubscriptionSink, SubscriptionMessage,
    core::{RpcResult, SubscriptionResult},
    proc_macros::rpc,
};
use reth_chain_state::CanonStateSubscriptions;
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::{EthereumEngineValidator, EthereumNode, node::EthereumAddOns},
    rpc::{api::eth::RpcNodeCore, eth::error::RpcPoolError},
};
use reth_node_builder::FullNodeComponents;
use revm_primitives::Bytes;
use tokio::sync::watch::Receiver;
use validation::{ValidationApi, ValidationApiConfig};

fn main() {
    Cli::<EthereumChainSpecParser, CliExt>::parse()
        .run(|builder, args| async move {
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(EthereumNode::components().map_pool(|pool| {
                    // TODO set cutom order on the pool?
                    pool
                }))
                .with_add_ons(EthereumAddOns::default())
                .extend_rpc_modules(move |ctx| {
                    if args.record_block_state {
                        // Start block state recorder
                        let notifications = ctx.provider().canonical_state_stream();
                        let block_record_dir = args.record_blocks_dir.clone();
                        tokio::spawn(run_block_state_recorder(notifications, block_record_dir));
                    }

                    if !args.enable_ext {
                        return Ok(());
                    }

                    // Handle to the transaction pool.
                    let pool = ctx.pool().clone();

                    // Block commit update stream.
                    let notifications = ctx.provider().canonical_state_stream();

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
                        ValidationApiConfig::new(
                            args.blacklist_provider.clone().unwrap_or_default(),
                            args.merger_private_key,
                        ),
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
#[derive(Debug, Clone, Default, clap::Args)]
struct CliExt {
    /// CLI flag to enable the txpool extension namespace
    #[arg(long)]
    pub enable_ext: bool,

    #[arg(long, default_value = "http://localhost:3520/blacklist")]
    pub blacklist_provider: Option<String>,

    #[arg(long, default_value_t = false)]
    pub record_block_state: bool,

    #[arg(long, default_value = "/root/blocks")]
    pub record_blocks_dir: String,

    // TODO: should we add a default value here?
    #[arg(long)]
    pub merger_private_key: String,
}

/// trait interface for a custom rpc namespace: `relay`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(server, namespace = "relay")]
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
