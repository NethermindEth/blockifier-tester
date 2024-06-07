use std::io::Read;

use starknet::{
    core::types::{BlockId, TransactionTraceWithHash},
    providers::{Provider, ProviderError},
};

use crate::{
    juno_manager::{JunoBranch, JunoManager, ManagerError},
    trace_transaction::TraceResult,
};

#[derive(Debug)]
pub struct TraceBlockReport {
    pub block: BlockId,
    pub post_response: Result<Vec<TransactionTraceWithHash>, ProviderError>,
    pub result: TraceResult,
    pub juno_did_crash: bool, // TODO return code?
    pub juno_output: Option<String>,
}

pub trait BlockTracer {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError>;
}

impl BlockTracer for JunoManager {
    async fn trace_block(&mut self, block_num: u64) -> Result<TraceBlockReport, ManagerError> {
        self.ensure_usable().await?;

        let block_id = BlockId::Number(block_num);
        println!("Tracing block {block_num}");
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;

        return match &trace_result {
            Ok(_) => Ok(TraceBlockReport {
                block: block_id,
                juno_did_crash: false,
                juno_output: None,
                result: TraceResult::Success,
                post_response: trace_result,
            }),
            Err(_) => Ok(TraceBlockReport {
                block: block_id,
                juno_did_crash: true,
                juno_output: None, // TODO
                result: TraceResult::Crash {
                    error: "".to_string(),
                },
                post_response: trace_result,
            }),
        };

        // let result_type: TraceResult;
        // let expect_juno_crash: bool;
        // match &trace_result {
        //     Ok(_) => {
        //         println!("Trace completed successfully");
        //         expect_juno_crash = false;
        //         result_type = TraceResult::Success;
        //     }
        //     Err(err) => {
        //         println!("Trace produced an error");
        //         result_type = TraceResult::Crash {
        //             error: format!("{err}"),
        //         };
        //         expect_juno_crash = true;
        //     }
        // };

        // let out_lines: Option<String> = if expect_juno_crash {
        //     println!("Expect juno to crash.");
        //     // TODO implement timeout
        //     let out = self
        //         .process
        //         .as_mut()
        //         .unwrap() // TODO make expect
        //         .stdout
        //         .as_mut()
        //         .expect("failed to get stdout from juno process");
        //     let mut lines = String::new();
        //     let _todo = out.read_to_string(&mut lines);
        //     Some(lines)
        // } else {
        //     None
        // };

        // let juno_did_crash = self.is_running().await?;

        // Ok(TraceBlockReport {
        //     block: block_id,
        //     juno_did_crash,
        //     juno_output: out_lines,
        //     result: result_type,
        //     post_response: trace_result,
        // })
    }
}

pub async fn block_main() -> Result<(), ManagerError> {
    let block_number = 640000;
    let mut juno_manager = JunoManager::new(JunoBranch::Native).await?;
    let trace_report = juno_manager.trace_block(block_number).await?;

    println!("//Done {block_number}");

    Ok(())
}
