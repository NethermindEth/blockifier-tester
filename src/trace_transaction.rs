use std::{fmt::Display, io::Read};

use starknet::{
    core::types::{FieldElement, StarknetError},
    providers::{Provider, ProviderError},
};

use crate::juno_manager::{JunoManager, ManagerError};

#[derive(Clone, Debug)]
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

pub struct TraceTransactionReport {
    transaction: FieldElement, // Hash of transaction.
    post_response: Result<starknet::core::types::TransactionTrace, ProviderError>,
    result: TraceResult,
    juno_did_crash: bool, // TODO return code?
    juno_output: Option<String>,
}

trait TransactionTracer {
    async fn trace_transaction(
        &mut self,
        transaction_hash: &str,
    ) -> Result<TraceTransactionReport, ManagerError>;
}

impl TransactionTracer for JunoManager {
    async fn trace_transaction(
        &mut self,
        transaction_hash: &str,
    ) -> Result<TraceTransactionReport, ManagerError> {
        self.ensure_usable().await?;
        let transaction = FieldElement::from_hex_be(transaction_hash)
            .map_err(|e| ManagerError::InternalError(format!("{}", e)))?;
        let trace_result = self.rpc_client.trace_transaction(transaction).await;

        // let result_type: TransactionResult;
        let result_type: TraceResult;
        match &trace_result {
            Ok(_) => {
                result_type = TraceResult::Success;
                println!("ok");
            }
            Err(err) => {
                result_type = TraceResult::from(err);
                println!("err: '{:?}' : type: '{}'", err, result_type);
            }
        };

        let expect_juno_crash: bool = matches!(result_type, TraceResult::Crash { error: _ });
        let juno_did_crash = self.is_running().await?;
        let out_lines: Option<String> = if expect_juno_crash {
            println!("Expect juno to crash.");
            // TODO implement timeout
            let out = self
                .process
                .stdout
                .as_mut()
                .expect("failed to get stdout from juno process");
            let mut lines = String::new();
            let _todo = out.read_to_string(&mut lines);
            Some(lines)
        } else {
            None
        };

        Ok(TraceTransactionReport {
            transaction,
            juno_did_crash,
            juno_output: out_lines,
            result: result_type,
            post_response: trace_result,
        })
    }
}

pub async fn transaction_hash_main() -> Result<(), ManagerError> {
    // let hash = "0x6faeed8967da5d3c0853b8cf4b40b55661a0f949678d5509254b643d133b769"; // DNE
    let hash = "0x07e3ace3b1c3f76b83b734b7a2ea990fb2823e931fb2ecef5d2677887aed9082"; // Crashes on native
    let mut juno_manager = JunoManager::new().await?;
    let trace_report = juno_manager.trace_transaction(hash).await?;
    println!("transaction: {:?}", trace_report.transaction);
    println!("juno: {:?}", trace_report.juno_output);
    println!("juno crashed? {}", trace_report.juno_did_crash);
    println!("result: {}", trace_report.result);
    match trace_report.post_response {
        Ok(item) => {
            println!("item: {:?}", item);
        }
        Err(err) => {
            println!("error: {}", err);
        }
    };

    println!("//Done {hash}");

    Ok(())
}
