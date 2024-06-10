mod block_tracer;
mod juno_manager;
mod transaction_simulator;
mod transaction_tracer;

use std::{fs, ops::Range, path::Path};

use block_tracer::{block_main, BlockTracer, TraceBlockReport};
use futures::future::join_all;
use itertools::Itertools;
use juno_manager::{JunoBranch, JunoManager, ManagerError};
use transaction_simulator::{log_block_report, simulate_main, TransactionSimulator};
use transaction_tracer::{transaction_hash_main, TraceResult};

fn should_run_block(block_number: &u64) -> bool {
    // !Path::new(&format!("./results/{block_number}.json")).exists() &&
    ![
        610508_u64, 610541_u64, 612572_u64, 612787_u64, 613138_u64, 613978_u64,
    ]
    .contains(&block_number)
}

async fn get_blocks_with_tx_count(
    block_range: &[u64],
    juno_manager: &mut JunoManager,
) -> Result<Vec<(u64, u64)>, ManagerError> {
    let mut blocks_with_tx_count = vec![];
    for block_number in block_range {
        blocks_with_tx_count.push((
            *block_number,
            juno_manager
                .get_block_transaction_count(starknet::core::types::BlockId::Number(*block_number))
                .await?,
        ));
    }
    Ok(blocks_with_tx_count)
}

// returns a list of (block number, transaction count), sorted by ascending transaction count
async fn get_sorted_blocks_with_tx_count() -> Vec<(u64, u64)> {
    let block_range = (610026..645300).filter(should_run_block);
    let mut juno_manager = JunoManager::new(JunoBranch::Native)
        .await
        .expect("Failed to start native juno");

    let mut blocks_with_tx_count =
        get_blocks_with_tx_count(&block_range.collect_vec(), &mut juno_manager)
            .await
            .unwrap();

    blocks_with_tx_count.sort_by(|lhs, rhs| Ord::cmp(&lhs.1, &rhs.1));

    juno_manager
        .ensure_dead()
        .await
        .expect("Failed to kill juno");

    blocks_with_tx_count
}

async fn try_native_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Native).await?;
    let result = juno_manager.trace_block(block_number).await;
    juno_manager
        .ensure_dead()
        .await
        .expect("Failed to kill native juno post trace");
    result
}

async fn try_base_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Base).await?;
    let result = juno_manager.trace_block(block_number).await;
    juno_manager
        .ensure_dead()
        .await
        .expect("Failed to kill base juno psot trace");
    result
}

#[tokio::main]
async fn main() {
    let blocks_with_tx_count = get_sorted_blocks_with_tx_count().await;

    for (block_number, tx_count) in blocks_with_tx_count {
        println!("Tracing block {block_number} with Native. It has {tx_count} transactions");

        let native_result = try_native_block_trace(block_number).await;

        match native_result {
            Ok(native_report) => {
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
            Err(err) => {
                println!("Got error {err:?}");
                println!(
                    "Simulating block {block_number} with Native. It has {tx_count} transactions"
                );
                let mut juno_manager = JunoManager::new(JunoBranch::Native).await.unwrap();
                let result = juno_manager.simulate_block(block_number).await.unwrap();
                // Note that this doesn't compare the reasons for failure or the result on a success
                let successes = result.iter().filter(|result| result.is_correct()).count();
                println!(
                    "Completed block {block_number} with {successes}/{} successses",
                    result.len()
                );
                log_block_report(block_number, result);
                juno_manager
                    .ensure_dead()
                    .await
                    .expect("Failed to kill native juno post simulate");
            }
        }
    }

    // for block_number in block_range {
    //     let trace_report = juno_manager.trace_block(block_number).await.unwrap();
    //     println!("block_id: {:?}", trace_report.block);
    //     println!("juno: {:?}", trace_report.juno_output);
    //     println!("juno crashed? {}", trace_report.juno_did_crash);
    //     println!("result: {}", trace_report.result);
    //     match trace_report.result {
    //         TraceResult::Success => {
    //             println!("Got success trace result");
    //             // TODO move these into a Display method and remove all the pub modifiers
    //             match trace_report.post_response {
    //                 Ok(items) => {
    //                     for item in items {
    //                         println!("item: {:?}", item);
    //                     }
    //                 }
    //                 Err(err) => {
    //                     println!("provider error: {}", err);
    //                 }
    //             };
    //         }
    //         TraceResult::Crash { error } => {
    //             println!(
    //                 "Got crash trace result with response: {:?}",
    //                 trace_report.post_response
    //             );
    //             let simulation_report = juno_manager.simulate_block(block_number).await;
    //             match simulation_report {
    //                 Ok(_) => todo!(),
    //                 Err(_) => todo!(),
    //             }
    //         }
    //         _ => todo!("Trace report: {:?}", trace_report), // Err(err) => match err {
    //                                                         //     ManagerError::ProviderError(err) => {
    //                                                         //         println!("ProviderError from trace: {err:?}");
    //                                                         //         let simulation_report = juno_manager.simulate_block(block_number).await;
    //                                                         //         match simulation_report {
    //                                                         //             Ok(_) => todo!(),
    //                                                         //             Err(_) => todo!(),
    //                                                         //         }
    //                                                         //     }
    //                                                         //     ManagerError::InternalError(msg) => {
    //                                                         //         todo!("{msg}")
    //                                                         //     }
    //                                                         // },
    //     }
    // }
    // transaction_hash_main().await.unwrap();
    // block_main().await.unwrap();
    // simulate_main().await.unwrap();
}
