use alloy_consensus::BlobTransactionValidationError;
use jsonrpsee::types::ErrorObject;
use reth_ethereum::{
    consensus::ConsensusError,
    evm::primitives::block::BlockExecutionError,
    node::core::rpc::result::{internal_rpc_err, invalid_params_rpc_err},
    provider::ProviderError,
};
use reth_node_builder::NewPayloadError;
use reth_primitives::GotExpected;
use revm_primitives::{Address, B256};

/// Errors thrown by the validation API.
#[derive(Debug, thiserror::Error)]
pub enum ValidationApiError {
    #[error("block gas limit mismatch: {_0}")]
    GasLimitMismatch(GotExpected<u64>),
    #[error("block gas used mismatch: {_0}")]
    GasUsedMismatch(GotExpected<u64>),
    #[error("block parent hash mismatch: {_0}")]
    ParentHashMismatch(GotExpected<B256>),
    #[error("block hash mismatch: {_0}")]
    BlockHashMismatch(GotExpected<B256>),
    #[error("missing latest block in database")]
    MissingLatestBlock,
    #[error("parent block not found")]
    MissingParentBlock,
    #[error("block is too old, outside validation window")]
    BlockTooOld,
    #[error("could not verify proposer payment")]
    ProposerPayment,
    #[error("invalid blobs bundle")]
    InvalidBlobsBundle,
    #[error("block accesses blacklisted address: {_0}")]
    Blacklist(Address),
    #[error(transparent)]
    Blob(#[from] BlobTransactionValidationError),
    #[error(transparent)]
    Consensus(#[from] ConsensusError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Execution(#[from] BlockExecutionError),
    #[error(transparent)]
    Payload(#[from] NewPayloadError),
    #[error("inclusion list not statisfied")]
    InclusionList,
}

impl From<ValidationApiError> for ErrorObject<'static> {
    fn from(error: ValidationApiError) -> Self {
        match error {
            ValidationApiError::GasLimitMismatch(_)
            | ValidationApiError::GasUsedMismatch(_)
            | ValidationApiError::ParentHashMismatch(_)
            | ValidationApiError::BlockHashMismatch(_)
            | ValidationApiError::Blacklist(_)
            | ValidationApiError::ProposerPayment
            | ValidationApiError::InvalidBlobsBundle
            | ValidationApiError::InclusionList
            | ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

            ValidationApiError::MissingLatestBlock
            | ValidationApiError::MissingParentBlock
            | ValidationApiError::BlockTooOld
            | ValidationApiError::Consensus(_)
            | ValidationApiError::Provider(_) => internal_rpc_err(error.to_string()),
            ValidationApiError::Execution(err) => match err {
                error @ BlockExecutionError::Validation(_) => {
                    invalid_params_rpc_err(error.to_string())
                }
                error @ BlockExecutionError::Internal(_) => internal_rpc_err(error.to_string()),
            },
            ValidationApiError::Payload(err) => match err {
                error @ NewPayloadError::Eth(_) => invalid_params_rpc_err(error.to_string()),
                error @ NewPayloadError::Other(_) => internal_rpc_err(error.to_string()),
            },
        }
    }
}
