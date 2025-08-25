use jsonrpsee::types::ErrorObject;
use reth_ethereum::{
    evm::primitives::block::BlockExecutionError,
    node::core::rpc::result::{internal_rpc_err, invalid_params_rpc_err},
    provider::ProviderError,
};
use reth_node_builder::NewPayloadError;

use crate::validation::error::{GetParentError, ValidationApiError};

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

impl From<BlockMergingApiError> for ErrorObject<'static> {
    fn from(error: BlockMergingApiError) -> Self {
        match error {
            BlockMergingApiError::MissingProposerPayment | BlockMergingApiError::InvalidProposerPayment => {
                invalid_params_rpc_err(error.to_string())
            }

            BlockMergingApiError::GetParent(_)
            | BlockMergingApiError::NextEvmEnvFail
            | BlockMergingApiError::RevenueAllocationReverted
            | BlockMergingApiError::ProposerPaymentReverted
            | BlockMergingApiError::ExecutionRequests
            | BlockMergingApiError::Provider(_) => internal_rpc_err(error.to_string()),

            BlockMergingApiError::Execution(err) => match err {
                error @ BlockExecutionError::Validation(_) => invalid_params_rpc_err(error.to_string()),
                error @ BlockExecutionError::Internal(_) => internal_rpc_err(error.to_string()),
            },
            BlockMergingApiError::Payload(err) => match err {
                error @ NewPayloadError::Eth(_) => invalid_params_rpc_err(error.to_string()),
                error @ NewPayloadError::Other(_) => internal_rpc_err(error.to_string()),
            },
            BlockMergingApiError::Validation(err) => err.into(),
        }
    }
}
