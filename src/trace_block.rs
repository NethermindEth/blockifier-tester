use std::io::Read;

use starknet::{
    core::types::{BlockId, TransactionTraceWithHash},
    providers::{Provider, ProviderError},
};

use crate::{
    juno_manager::{JunoManager, ManagerError},
    trace_transaction::TraceResult,
};

pub struct TraceBlockReport {
    block: BlockId,
    post_response: Result<Vec<TransactionTraceWithHash>, ProviderError>,
    result: TraceResult,
    juno_did_crash: bool, // TODO return code?
    juno_output: Option<String>,
}

trait BlockTracer {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError>;
}

impl BlockTracer for JunoManager {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError> {
        self.ensure_usable().await?;

        let block_id = BlockId::Number(block_num);
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;

        let result_type: TraceResult;
        let expect_juno_crash: bool;
        match &trace_result {
            Ok(_) => {
                expect_juno_crash = false;
                result_type = TraceResult::Success;
            }
            Err(err) => {
                result_type = TraceResult::Crash {
                    error: format!("{err}"),
                };
                expect_juno_crash = true;
            }
        };

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

        let juno_did_crash = self.is_running().await?;

        Ok(TraceBlockReport {
            block: block_id,
            juno_did_crash,
            juno_output: out_lines,
            result: result_type,
            post_response: trace_result,
        })
    }
}

pub async fn block_main() -> Result<(), ManagerError> {
    let block_number = 640000;
    let mut juno_manager = JunoManager::new().await?;
    let trace_report = juno_manager.trace_block(block_number).await?;
    println!("block_id: {:?}", trace_report.block);
    println!("juno: {:?}", trace_report.juno_output);
    println!("juno crashed? {}", trace_report.juno_did_crash);
    println!("result: {}", trace_report.result);
    match trace_report.post_response {
        Ok(items) => {
            for item in items {
                println!("item: {:?}", item);
            }
        }
        Err(err) => {
            println!("provider error: {}", err);
        }
    };

    println!("//Done {block_number}");

    Ok(())
}
