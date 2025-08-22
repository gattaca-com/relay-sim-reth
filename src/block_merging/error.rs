use reth_ethereum::{evm::primitives::block::BlockExecutionError, provider::ProviderError};
use reth_node_builder::NewPayloadError;

use crate::validation::{GetParentError, ValidationApiError};

/// Errors thrown by the block merging API.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BlockMergingApiError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Execution(#[from] BlockExecutionError),
    #[error(transparent)]
    Payload(#[from] NewPayloadError),
    #[error("failed to create EvmEnv for next block")]
    NextEvmEnvFail,
    #[error("failed to decode execution requests")]
    ExecutionRequests,
    #[error("could not find a proposer payment tx")]
    MissingProposerPayment,
    #[error("could not verify proposer payment tx")]
    InvalidProposerPayment,
    #[error("revenue allocation tx reverted")]
    RevenueAllocationReverted,
    #[error("proposer payment tx reverted")]
    ProposerPaymentReverted,
    #[error("validation: {0}")]
    Validation(#[from] ValidationApiError),
    #[error("could not find parent block: {_0}")]
    GetParent(#[from] GetParentError),
}
