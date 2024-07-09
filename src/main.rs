mod block_tracer;
mod cache;
mod general_trace_comparison;
mod graph;
mod juno_manager;
mod transaction_simulator;
mod transaction_tracer;
mod utils;

use anyhow::Context;
use block_tracer::{BlockTracer, TraceBlockReport};
use cache::get_sorted_blocks_with_tx_count;
use chrono::Local;
use clap::{arg, command, value_parser, ArgAction, Command};
use core::panic;
use env_logger::Env;
use general_trace_comparison::generate_block_comparison;
use itertools::Itertools;
use juno_manager::{JunoBranch, JunoManager};
use log::{debug, info, warn};
use starknet::core::types::{FieldElement, TransactionTraceWithHash};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use transaction_simulator::{BlockSimulationReport, SimulationStrategy, TransactionSimulator};
use transaction_tracer::TraceResult;
use utils::try_write_to_file;
use graph::DependencyMap;

async fn try_native_block_trace(block_number: u64) -> Result<TraceBlockReport, anyhow::Error> {
    try_block_trace(block_number, JunoBranch::Native).await
}

async fn try_base_block_trace(block_number: u64) -> Result<TraceBlockReport, anyhow::Error> {
    try_block_trace(block_number, JunoBranch::Base).await
}

async fn try_block_trace(
    block_number: u64,
    branch: JunoBranch,
) -> Result<TraceBlockReport, anyhow::Error> {
    // let branch = JunoBranch::Base;
    let path = format!("./dump/trace-{block_number}-{}.json", branch);
    debug!(
        "try_block_trace. block: {}\tbranch: {}\tpath: {}",
        block_number,
        branch,
        path.as_str()
    );
    let cache_path = Path::new(&path);
    utils::memoized_call(cache_path, || async {
        let mut juno_manager = JunoManager::new(branch)
            .await
            .map_err(|err| anyhow::anyhow!(err))?;
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

fn results_exist_for_block(block: u64) -> bool {
    Path::new(&format!("results/trace-{block}.json")).exists()
        || Path::new(&format!("results/block-{block}.json")).exists()
        || Path::new(&format!("results/err-{block}.json")).exists()
}

fn add_report_dependencies(
    report: &transaction_simulator::SimulationReport,
    dependencies: Option<(
        DependencyMap,
        DependencyMap,
    )>,
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

async fn execute_traces(start_block: u64, end_block: u64, should_run_known: bool) {
    let blocks_with_tx_count = get_sorted_blocks_with_tx_count(start_block, end_block)
        .await
        .unwrap();

    for (block_number, tx_count) in blocks_with_tx_count {
        if !should_run_known && results_exist_for_block(block_number) {
            info!("Skipping block {block_number} because results exist (use --run-known to run anyways)");
            continue;
        }

        info!("Tracing block {block_number} with Base. It has {tx_count} transactions");
        let base_result = try_base_block_trace(block_number).await;

        info!("Tracing block {block_number} with Native. It has {tx_count} transactions");
        let native_result = try_native_block_trace(block_number).await;

        let should_simulate = native_result
            .as_ref()
            .map(|report| report.result != TraceResult::Success)
            .unwrap_or(true);

        if should_simulate {
            info!("Failed to trace block with Native, got {native_result:?}");

            let simulate_block_path = format!("./results/block-{}.json", block_number);
            let simulate_block_path = Path::new(simulate_block_path.as_str());

            // If we've output this <result or error>, then skip this.
            if simulate_block_path.exists() {
                continue;
            }

            let mut juno_manager = JunoManager::new(JunoBranch::Native).await.unwrap();
            let result = juno_manager
                .simulate_block(block_number, SimulationStrategy::Binary)
                .await;

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
                    // log_block_report(block_number, reports_with_dependencies);
                    let _ =
                        utils::try_write_to_file(simulate_block_path, &reports_with_dependencies)
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
                    let _ = utils::try_write_to_file(simulate_block_path, &err_string.as_str())
                        .await
                        .inspect_err(|write_err| {
                            warn!("failed to write error. Write error: {write_err:?}")
                        });
                }
            };
            debug!("after match block");
        } else {
            let native_report = native_result.unwrap();
            info!("{}", native_report.result);

            match base_result {
                Ok(base_report) => {
                    info!("{}", base_report.result);
                    let compare_trace_path = format!("results/trace-{block_number}.json");
                    let comparison = generate_block_comparison(base_report, native_report);
                    let _ = try_write_to_file(Path::new(compare_trace_path.as_str()), &comparison)
                        .await
                        .context(format!("Writing comparison to log: {compare_trace_path}"))
                        .inspect_err(|write_err| {
                            warn!("Failed to log comparison. Write error: {write_err:?}")
                        });
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
    }
}

#[tokio::main]
async fn main() {
    setup_env_logger();

    let run_known_flag =
                  arg!(<run_known> "Forces action even if an output file (block- or trace-) already exists for block")
                    .long("run-known")
                    .action(ArgAction::SetTrue)
                    .required(false);
    let cli = command!()
        .subcommand(
            Command::new("block")
                .about("traces a single block")
                .arg(arg!(<block_num> "block number to trace").value_parser(value_parser!(u64)))
                .arg(run_known_flag.clone()),
        )
        .subcommand(
            Command::new("range")
                .about("traces a block range")
                .arg(
                    arg!(<first_block_num> "inclusive initial block number")
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    arg!(<last_block_num> "exclusive last block number")
                        .value_parser(value_parser!(u64)),
                )
                .arg(run_known_flag),
        )
        .get_matches();

    match cli.subcommand() {
        Some(("block", args)) => {
            let should_run_known = args.get_one::<bool>("run_known").unwrap().to_owned();
            let block_num = args.get_one::<u64>("block_num").unwrap().to_owned();
            execute_traces(block_num, block_num + 1, should_run_known).await;
        }
        Some(("range", args)) => {
            let first_block_num = args.get_one::<u64>("first_block_num").unwrap().to_owned();
            let last_block_num = args.get_one::<u64>("last_block_num").unwrap().to_owned();
            if last_block_num <= first_block_num {
                panic!("first_block_num must be higher than last_block_num");
            }
            let should_run_known = args.get_one::<bool>("run_known").unwrap().to_owned();
            execute_traces(first_block_num, last_block_num, should_run_known).await;
        }
        Some((cmd, _)) => panic!("Unknown {cmd} "),
        None => panic!("Expecting either `block` or `range` sub-commands"),
    }
}
