mod juno_manager;
mod transaction_simulator;
mod block_tracer;
mod transaction_tracer;

use juno_manager::{JunoBranch, JunoManager, ManagerError};
use transaction_simulator::{simulate_main, TransactionSimulator};
use block_tracer::{block_main, BlockTracer};
use transaction_tracer::{transaction_hash_main, TraceResult};

#[tokio::main]
async fn main() {
    let block_range = 645000..645100;

    let mut juno_manager = JunoManager::new(JunoBranch::Native)
        .await
        .expect("Failed to start native juno");
    for block_number in block_range {
        let trace_report = juno_manager.trace_block(block_number).await.unwrap();
        println!("block_id: {:?}", trace_report.block);
        println!("juno: {:?}", trace_report.juno_output);
        println!("juno crashed? {}", trace_report.juno_did_crash);
        println!("result: {}", trace_report.result);
        match trace_report.result {
            TraceResult::Success => {
                println!("Got success trace result");
                // TODO move these into a Display method and remove all the pub modifiers
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
            }
            TraceResult::Crash { error } => {
                println!("Got crash trace result with response: {:?}", trace_report.post_response);
                let simulation_report = juno_manager.simulate_block(block_number).await;
                match simulation_report {
                    Ok(_) => todo!(),
                    Err(_) => todo!(),
                }    
            }
            _ => todo!("Trace report: {:?}", trace_report)
            // Err(err) => match err {
            //     ManagerError::ProviderError(err) => {
            //         println!("ProviderError from trace: {err:?}");
            //         let simulation_report = juno_manager.simulate_block(block_number).await;
            //         match simulation_report {
            //             Ok(_) => todo!(),
            //             Err(_) => todo!(),
            //         }
            //     }
            //     ManagerError::InternalError(msg) => {
            //         todo!("{msg}")
            //     }
            // },
        }
    }
    // transaction_hash_main().await.unwrap();
    // block_main().await.unwrap();
    // simulate_main().await.unwrap();
}
