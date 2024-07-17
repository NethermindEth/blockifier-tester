use crate::graph;

use itertools::Itertools;
use log::debug;
use serde::Serialize;
use starknet::{
    core::types::{BlockId, FieldElement, TransactionTraceWithHash},
    providers::Provider,
};

use crate::{
    juno_manager::{JunoManager, ManagerError},
    transaction_tracer::TraceResult,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionTraceReport {
    pub trace: TransactionTraceWithHash,
    pub contract_dependencies: Vec<String>,
    pub storage_dependencies: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TraceBlockReport {
    pub block_num: u64,
    pub post_response: Option<Vec<TransactionTraceReport>>,
    pub result: TraceResult,
}
impl TraceBlockReport {
    fn new(
        block_num: u64,
        result: TraceResult,
        traces: Vec<TransactionTraceWithHash>,
        contract_dependencies: std::collections::HashMap<FieldElement, Vec<String>>,
        storage_dependencies: std::collections::HashMap<FieldElement, Vec<String>>,
    ) -> Self {
        let transaction_reports = traces
            .into_iter()
            .map(|trace| TransactionTraceReport {
                contract_dependencies: contract_dependencies[&trace.transaction_hash].clone(),
                storage_dependencies: storage_dependencies[&trace.transaction_hash].clone(),
                trace,
            })
            .collect_vec();
        Self {
            block_num,
            post_response: Some(transaction_reports),
            result,
        }
    }
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
        debug!("Finished tracing block {block_num}");
        self.ensure_dead().await?;

        match trace_result {
            Ok(traces) => {
                let (contract_dependencies, storage_dependencies) =
                    graph::get_dependencies(traces.iter());

                Ok(TraceBlockReport::new(
                block_num,
                TraceResult::Success,
                traces,
                    contract_dependencies,
                    storage_dependencies,
                ))
            }

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
