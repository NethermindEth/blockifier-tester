mod block_tracer;
mod cache;
mod juno_manager;
mod transaction_simulator;
mod transaction_tracer;

use block_tracer::{BlockTracer, TraceBlockReport};
use cache::get_sorted_blocks_with_tx_count;
use chrono::Local;
use juno_manager::{JunoBranch, JunoManager, ManagerError};
use std::io::Write;
use std::{fs, path::Path};
use transaction_simulator::{log_block_report, SimulationStrategy, TransactionSimulator};
use transaction_tracer::TraceResult;

const RERUNNING_AFTER_FIXES: bool = false;

fn should_run_block(block_number: &u64) -> bool {
    RERUNNING_AFTER_FIXES
        || (!Path::new(&format!("./results/{block_number}.json")).exists()
            && !Path::new(&format!("./results/trace-{block_number}.json")).exists()
            && ![
                610508_u64, 610541_u64, 612572_u64, 612787_u64, 613138_u64, 613978_u64,
            ]
            .contains(block_number))
}

async fn try_native_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Native).await?;
    juno_manager.trace_block(block_number).await
}

async fn try_base_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Base).await?;
    juno_manager.trace_block(block_number).await
}

#[tokio::main]
async fn main() {
    // run with RUST_LOG=juno_compare_traces to log everything
    env_logger::builder()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {}: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .init();
    let start = 610026;
    let end = 645300;
    let blocks_with_tx_count = get_sorted_blocks_with_tx_count(start, end)
        .await
        .unwrap()
        .into_iter()
        .filter(|(block_number, _)| should_run_block(block_number));

    for (block_number, tx_count) in blocks_with_tx_count {
        println!("Tracing block {block_number} with Native. It has {tx_count} transactions");

        let native_result = try_native_block_trace(block_number).await;
        let should_simulate = native_result
            .as_ref()
            .map(|report| report.result != TraceResult::Success)
            .unwrap_or(true);

        if should_simulate {
            println!("Failed to trace block with Native, got {native_result:?}");
            println!("Simulating block {block_number} with Native. It has {tx_count} transactions");
            let mut juno_manager = JunoManager::new(JunoBranch::Native).await.unwrap();
            let result = juno_manager
                .simulate_block(block_number, SimulationStrategy::Binary)
                .await
                .unwrap();
            // Note that this doesn't compare the reasons for failure or the result on a success
            let successes = result.iter().filter(|result| result.is_correct()).count();
            println!(
                "Completed block {block_number} with {successes}/{} successses",
                result.len()
            );
            log_block_report(block_number, result);
        } else {
            let native_report = native_result.unwrap();
            println!("{}", native_report.result);
            println!("Tracing block {block_number} with Base. It has {tx_count} transactions");
            let base_result = try_base_block_trace(block_number).await;
            match base_result {
                Ok(base_report) => {
                    println!("{}", base_report.result);
                    fs::write(
                        Path::new(&format!("./results/trace-{}.json", block_number)),
                        format!(
                            "{{\n
                            \"Block number\": {block_number},\n
                            \"Base success\": \"{}\",\n
                            \"Native success\": \"{}\",\n
                            \"Base trace\": \"{:?}\",\n
                            \"Native trace\": \"{:?}\",\n
                        }}",
                            base_report.result,
                            native_report.result,
                            base_report.post_response,
                            native_report.post_response,
                        ),
                    )
                    .expect("Failed to write block report");
                }
                Err(err) => {
                    println!("{err:?}");
                }
            }
        }
    }
}
