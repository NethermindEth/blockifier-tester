mod block_tracer;
mod cache;
mod cli;
mod graph;
mod juno_manager;
mod trace_comparison;
mod transaction_simulator;
mod transaction_tracer;
mod utils;

use crate::cli::{Cli, Commands};
use anyhow::Context;
use block_tracer::{BlockTracer, TraceBlockReport};
use cache::get_sorted_blocks_with_tx_count;
use chrono::Local;
use clap::Parser;
use core::panic;
use env_logger::Env;
use graph::DependencyMap;
use itertools::Itertools;
use juno_manager::{JunoBranch, JunoManager, ManagerError};
use log::{debug, error, info, warn};
use starknet::core::types::{FieldElement, SimulationFlag, TransactionTraceWithHash};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use trace_comparison::generate_block_comparison;
use transaction_simulator::BlockSimulationReport;
use transaction_simulator::{SimulationStrategy, TransactionSimulator};
use transaction_tracer::TraceResult;
use utils::try_write_to_file;

async fn try_block_trace(
    block_number: u64,
    juno_manager: & mut JunoManager,
) -> Result<TraceBlockReport, anyhow::Error> {
    let path = format!("./dump/trace-{block_number}-{}.json", juno_manager.branch);
    debug!(
        "try_block_trace. block: {block_number}\tbranch: {}\tpath: {}",
        juno_manager.branch,
        path.as_str()
    );
    let cache_path = Path::new(&path);
    utils::memoized_call(cache_path, || async {
        juno_manager
            .trace_block(block_number)
            .await
            .map_err(|err| anyhow::anyhow!(err))
    })
    .await
}

fn setup_env_logger() {
    env_logger::Builder::from_env(Env::default().filter_or("LOG_LEVEL", "debug"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {}: {}",
                Local::now().format("%d %H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .init();
}

fn add_report_dependencies(
    report: &transaction_simulator::SimulationReport,
    dependencies: Option<(DependencyMap, DependencyMap)>,
) -> serde_json::Value {
    // let map = serde_json::Map::new();
    let mut obj = serde_json::value::to_value(report).unwrap();
    if let serde_json::Value::Object(ref mut map) = obj {
        let values = if let Some((contracts, storage)) = dependencies {
            (
                serde_json::to_value(contracts[&report.tx_hash].clone()).unwrap(),
                serde_json::to_value(storage[&report.tx_hash].clone()).unwrap(),
            )
        } else {
            (
                serde_json::to_value("Unknown").unwrap(),
                serde_json::to_value("Unknown").unwrap(),
            )
        };
        map.insert("contract_dependencies".to_string(), values.0);
        map.insert("storage_dependencies".to_string(), values.1);
    }
    obj
}

fn add_dependencies(report: transaction_simulator::BlockSimulationReport) -> serde_json::Value {
    let dependencies = get_dependencies(&report);
    let mut values = Vec::<serde_json::Value>::new();
    for transaction_report in &report.simulated_reports {
        let next_value = add_report_dependencies(transaction_report, Some(dependencies.clone()));
        values.push(next_value);
    }

    serde_json::value::to_value(values).unwrap()
}

fn get_dependencies(
    simulation_report: &BlockSimulationReport,
) -> (
    HashMap<FieldElement, Vec<String>>,
    HashMap<FieldElement, Vec<String>>,
) {
    let transaction_traces_with_hashes = simulation_report
        .transactions_list
        .iter()
        .zip(simulation_report.simulated_transactions.iter())
        .map(|(to_simulate, simulated)| TransactionTraceWithHash {
            transaction_hash: to_simulate.hash,
            trace_root: simulated.transaction_trace.clone(),
        })
        .collect_vec();
    graph::get_dependencies(transaction_traces_with_hashes.iter())
}

fn results_exist_for_block(block: u64) -> bool {
    Path::new(&format!("results/trace-{}.json", block)).exists()
        || Path::new(&format!("results/block-{}.json", block)).exists()
}

async fn execute_traces(
    start_block: u64,
    end_block: u64,
    should_run_known: bool,
    simulation_flags: Vec<SimulationFlag>,
) -> Result<(), ManagerError> {
    let mut base_juno = JunoManager::new(JunoBranch::Base).await?;
    let blocks_with_tx_count =
        get_sorted_blocks_with_tx_count(&mut base_juno, start_block, end_block)
            .await
            .unwrap();

    for (block_number, tx_count) in blocks_with_tx_count {
        if !should_run_known && results_exist_for_block(block_number) {
            info!("Skipping block {block_number} because results exist (use --run-known to run anyways)");
            continue;
        }

        info!("TRACING block {block_number} with Base. It has {tx_count} transactions");
        // First branch is a succesful block trace with Base
        // Second branch is an unexpected crash by Juno/Blockifier/nNative
        match try_block_trace(block_number, &mut base_juno).await {
            Ok(base_report) => {
                if base_report.result != TraceResult::Success {
                    // todo: prettier handling, but low prio.
                    let trace = serde_json::to_string_pretty(&base_report)
                        .unwrap_or(format!("Serialization failed!\n{base_report:?}"));
                    panic!("Tracing with base juno is always expected to work. Check your base juno bin and config. Error:\n{}",trace);
                }

                info!("Switching from Base Juno to Native Juno");
                base_juno.ensure_dead().await?;
                let mut native_juno = JunoManager::new(JunoBranch::Native).await?;

                info!("TRACING block {block_number} with Native. It has {tx_count} transactions");
                // First branch is succesful block trace with Native
                // Second branch is an unhandled crash by the blockifier/native during tracing
                // Third branch is an unexpected crash by Juno Manager
                match native_juno.trace_block(block_number).await {
                    Ok(native_report) if native_report.result == TraceResult::Success => {
                        info!("SUCCESS tracing block with native");

                        let compare_trace_path = format!("results/trace-{block_number}.json");
                        let comparison = generate_block_comparison(base_report, native_report);
                        let _ =
                            try_write_to_file(Path::new(compare_trace_path.as_str()), &comparison)
                                .await
                                .context(format!("Writing comparison to log: {compare_trace_path}"))
                                .inspect_err(|write_err| {
                                    warn!("Failed to log comparison. Write error: {write_err:?}")
                                });
                    }
                    Ok(native_report) => {
                        // When tracing a block with native fails, the next step is performing a
                        // binary search over the transactions searching for the one that crashes
                        info!("Failed to trace block with Native, got {native_report:?}");
                        info!("SIMULATING block {block_number} with Native. It has {tx_count} transactions");

                        // We make sure Natve Juno get properly killed before proceeding.
                        native_juno.ensure_dead().await?;
                        native_juno.ensure_usable().await?;
                        let result = native_juno
                            .simulate_block(
                                block_number,
                                SimulationStrategy::Binary,
                                &simulation_flags,
                            )
                            .await;

                        let simulate_block_path = format!("./results/block-{}.json", block_number);
                        let simulate_block_path = Path::new(simulate_block_path.as_str());
                        match result {
                            // Note that this doesn't compare the reasons for failure or the result on a success
                            Ok(result) => {
                                let successes = result
                                    .simulated_reports
                                    .iter()
                                    .filter(|result| result.is_correct())
                                    .count();
                                info!(
                                    "Completed block {block_number} with {successes}/{} successes",
                                    result.simulated_reports.len()
                                );
                                let reports_with_dependencies = add_dependencies(result);
                                let _ = utils::try_write_to_file(
                                    simulate_block_path,
                                    &reports_with_dependencies,
                                )
                                .await
                                .inspect_err(|write_err| {
                                    warn!(
                                    "failed to write block simulation. Write error: {write_err:?}"
                                )
                                });
                            }
                            Err(err) => {
                                let err_string = format!("{err:?}");
                                warn!("Error simulating transactions: {}", err_string);
                                let _ = utils::try_write_to_file(
                                    simulate_block_path,
                                    &err_string.as_str(),
                                )
                                .await
                                .inspect_err(|write_err| {
                                    warn!("failed to write error. Write error: {write_err:?}")
                                });
                            }
                        };
                    }
                    Err(err) => {
                        warn!("{err:?}");
                        let err_log_path = format!("results/err-{block_number}.json");
                        let err_string = format!("{err:?}");
                        let _ = utils::try_write_to_file(Path::new(&err_log_path), &err_string)
                            .await
                            .context(format!("Writing error to log: {err_log_path}"))
                            .inspect_err(|write_err| {
                                warn!("Failed to log error. Write error: {write_err:?}")
                            });
                    }
                };
            }
            Err(err) => {
                warn!("{err:?}");
                let err_log_path = format!("results/err-{block_number}.json");
                let err_string = format!("{err:?}");
                let _ = utils::try_write_to_file(Path::new(&err_log_path), &err_string)
                    .await
                    .context(format!("Writing error to log: {err_log_path}"))
                    .inspect_err(|write_err| {
                        warn!("Failed to log error. Write error: {write_err:?}")
                    });
            }
        }
    }

    Ok(())
}

async fn prepare_directories() {
    info!("Preparing directories");

    tokio::fs::create_dir_all("./results").await.unwrap();
    tokio::fs::create_dir_all("./cache").await.unwrap();
    tokio::fs::create_dir_all("./results/base").await.unwrap();
    tokio::fs::create_dir_all("./results/native").await.unwrap();
}

#[tokio::main]
async fn main() -> Result<(), ManagerError> {
    setup_env_logger();
    prepare_directories().await;

    let cli = Cli::parse();

    let run_known = cli.run_known;

    let mut simulation_flags = vec![];

    if cli.skip_validate {
        info!("Running a simulation with SKIP_VALIDATE flag");
        simulation_flags.push(SimulationFlag::SkipValidate)
    }

    if cli.skip_fee_charge {
        info!("Running a simulation with SKIP_FEE_CHARGE flag");
        simulation_flags.push(SimulationFlag::SkipFeeCharge)
    }

    match cli.command {
        Commands::Block { block_num } => {
            let start_block = block_num;
            let end_block = block_num + 1;
            execute_traces(start_block, end_block, run_known, simulation_flags).await?;
        }
        Commands::Range {
            start_block_num,
            end_block_num,
        } => {
            execute_traces(start_block_num, end_block_num, run_known, simulation_flags).await?;
        }
    }

    Ok(())
}
