use log::debug;
use serde::Serialize;
use starknet::{
    core::types::{BlockId, TransactionTraceWithHash},
    providers::Provider,
};

use crate::{
    juno_manager::{JunoManager, ManagerError},
    transaction_tracer::TraceResult,
};

#[derive(Debug, Serialize)]
pub struct TraceBlockReport {
    pub block_num: u64,
    pub post_response: Option<Vec<TransactionTraceWithHash>>,
    pub result: TraceResult,
}

pub trait BlockTracer {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError>;
}

impl BlockTracer for JunoManager {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError> {
        self.ensure_usable().await?;

        let block_id = BlockId::Number(block_num);
        debug!("rpc call to trace_block_transactions {block_num}");
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;
        debug!("rpc call completed");

        match trace_result {
            Ok(trace_result) => Ok(TraceBlockReport {
                block_num,
                result: TraceResult::Success,
                post_response: Some(trace_result),
            }),
            Err(provider_error) => Ok(TraceBlockReport {
                block_num,
                result: TraceResult::Crash {
                    error: provider_error.to_string(),
                },
                post_response: None,
            }),
        }
    }
}
