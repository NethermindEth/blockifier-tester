use log::{debug, info};
use starknet::{
    core::types::{BlockId, TransactionTraceWithHash},
    providers::{Provider, ProviderError},
};

use crate::{
    juno_manager::{JunoBranch, JunoManager, ManagerError},
    transaction_tracer::TraceResult,
};

#[derive(Debug)]
pub struct TraceBlockReport {
    pub block: BlockId,
    pub post_response: Result<Vec<TransactionTraceWithHash>, ProviderError>,
    pub result: TraceResult,
}

pub trait BlockTracer {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError>;
}

impl BlockTracer for JunoManager {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError> {
        self.ensure_usable().await?;

        let block_id = BlockId::Number(block_num);
        debug!("Tracing block {block_num}");
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;
        self.ensure_dead().await?;

        match &trace_result {
            Ok(_) => Ok(TraceBlockReport {
                block: block_id,
                result: TraceResult::Success,
                post_response: trace_result,
            }),
            Err(_) => Ok(TraceBlockReport {
                block: block_id,
                result: TraceResult::Crash {
                    error: "".to_string(),
                },
                post_response: trace_result,
            }),
        }
    }
}

#[allow(dead_code)]
pub async fn block_main() -> Result<(), ManagerError> {
    let block_number = 640000;
    let mut juno_manager = JunoManager::new(JunoBranch::Native).await?;
    let trace_report = juno_manager.trace_block(block_number).await?;

    info!("//Done {block_number}");
    info!("{trace_report:?}");

    Ok(())
}
