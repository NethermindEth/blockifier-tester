use std::fmt::Display;

use serde::{Deserialize, Serialize};

use starknet::{
    core::types::{StarknetError, TransactionTraceWithHash},
    providers::ProviderError,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TraceResult {
    Success,
    OtherError(String),
    NotFound,
    Crash { error: String },
}

impl From<&ProviderError> for TraceResult {
    fn from(value: &ProviderError) -> Self {
        match value {
            ProviderError::StarknetError(starknet_err) => match starknet_err {
                StarknetError::FailedToReceiveTransaction => {
                    Self::OtherError("FailedToReceiveTransaction".to_string())
                }
                StarknetError::ContractNotFound => Self::NotFound,
                StarknetError::BlockNotFound => Self::NotFound,
                StarknetError::ClassHashNotFound => Self::NotFound,
                StarknetError::TransactionHashNotFound => Self::NotFound,
                StarknetError::UnexpectedError(other) => Self::OtherError(other.clone()),
                _ => Self::OtherError(starknet_err.to_string()),
            },
            ProviderError::RateLimited => {
                Self::OtherError("ProviderError::RateLimited".to_string())
            }
            ProviderError::ArrayLengthMismatch => {
                Self::OtherError("ProviderError::ArrayLengthMismatch".to_string())
            }
            ProviderError::Other(other) => Self::Crash {
                error: other.to_string(),
            },
        }
    }
}

impl Display for TraceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            TraceResult::Success => write!(f, "TraceResult::Success"),
            TraceResult::OtherError(error) => write!(f, "TraceResult::OtherError: '{}'", error),
            TraceResult::NotFound => write!(f, "TraceResult::NotFound"),
            TraceResult::Crash { error } => write!(f, "TraceResult::Crash: '{}'", error),
        }
    }
}
