mod block_tracer;
mod cache;
mod general_trace_comparison;
mod juno_manager;
mod transaction_simulator;
mod transaction_tracer;

use block_tracer::{BlockTracer, TraceBlockReport};
use cache::get_sorted_blocks_with_tx_count;
use chrono::Local;
use clap::{arg, command, value_parser, ArgAction, Command};
use core::panic;
use general_trace_comparison::generate_block_comparison;
use juno_manager::{JunoBranch, JunoManager, ManagerError};
use log::{info, warn};
use std::io::Write;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use transaction_simulator::{log_block_report, SimulationStrategy, TransactionSimulator};
use transaction_tracer::TraceResult;

async fn try_native_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Native).await?;
    juno_manager.trace_block(block_number).await
}

async fn try_base_block_trace(block_number: u64) -> Result<TraceBlockReport, ManagerError> {
    let mut juno_manager = JunoManager::new(JunoBranch::Base).await?;
    juno_manager.trace_block(block_number).await
}

// Creates a file in ./results/err-{`block_number`}.json with the failure reason
async fn log_trace_crash(block_number: u64, err: ManagerError) {
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(format!("./results/err-{block_number}.json"))
        .await
        .expect("Failed to open log file");
    if let Err(write_err) = log_file.write_all(format!("{err:?}").as_bytes()).await {
        warn!("Failed to write err with error: '{write_err}'");
    }
}

// Creates a file in ./results/trace-{`block_number`}.json with the a full trace comparison between
// base blockifier and native blockifier results
async fn log_trace_comparison(
    block_number: u64,
    native_report: TraceBlockReport,
    base_report: TraceBlockReport,
) {
    let comparison = generate_block_comparison(base_report, native_report);

    let mut buffer = Vec::new();
    serde_json::to_writer_pretty(&mut buffer, &comparison).unwrap();

    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(format!("./results/trace-{block_number}.json"))
        .await
        .expect("Failed to open log file");

    let mut writer = BufWriter::new(log_file);
    writer.write_all(&buffer).await.unwrap();
    writer.flush().await.unwrap();
}

fn setup_env_logger() {
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
}

fn results_exist_for_block(block: u64) -> bool {
    Path::new(&format!("results/trace-{}.json", block)).exists()
        || Path::new(&format!("results/block-{}.json", block)).exists()
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

        info!("Tracing block {block_number} with Native. It has {tx_count} transactions");

        let native_result = try_native_block_trace(block_number).await;
        let should_simulate = native_result
            .as_ref()
            .map(|report| report.result != TraceResult::Success)
            .unwrap_or(true);

        if should_simulate {
            info!("Failed to trace block with Native, got {native_result:?}");
            info!("Simulating block {block_number} with Native. It has {tx_count} transactions");
            let mut juno_manager = JunoManager::new(JunoBranch::Native).await.unwrap();
            let result = juno_manager
                .simulate_block(block_number, SimulationStrategy::Binary)
                .await
                .unwrap();
            // Note that this doesn't compare the reasons for failure or the result on a success
            let successes = result.iter().filter(|result| result.is_correct()).count();
            info!(
                "Completed block {block_number} with {successes}/{} successes",
                result.len()
            );
            log_block_report(block_number, result);
        } else {
            let native_report = native_result.unwrap();
            info!("{}", native_report.result);
            info!("Tracing block {block_number} with Base. It has {tx_count} transactions");
            let base_result = try_base_block_trace(block_number).await;
            match base_result {
                Ok(base_report) => {
                    info!("{}", base_report.result);
                    log_trace_comparison(block_number, native_report, base_report).await;
                }
                Err(err) => {
                    warn!("{err:?}");
                    log_trace_crash(block_number, err).await;
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
