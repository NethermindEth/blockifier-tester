use log::debug;
use serde::{Deserialize, Serialize};
use starknet::{core::types::BlockId, providers::Provider};

use crate::{
    juno_manager::{JunoManager, ManagerError},
    transaction_tracer::TraceResult,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceBlockReport {
    pub block_num: u64,
    pub result: TraceResult,
}

pub trait BlockTracer {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError>;
}

impl BlockTracer for JunoManager {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError> {
        self.start_juno().await?;

        let block_id = BlockId::Number(block_num);
        debug!("rpc call to trace_block_transactions {block_num}");
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;
        debug!("rpc call completed");

        match trace_result {
            Ok(trace_result) => Ok(TraceBlockReport {
                block_num,
                result: TraceResult::Success(trace_result),
            }),
            Err(provider_error) => Ok(TraceBlockReport {
                block_num,
                result: TraceResult::Crash {
                    error: provider_error.to_string(),
                },
            }),
        }
    }
}
