mod block_tracer;
mod cache;
mod cli;
mod dependencies;
mod graph;
mod io;
mod juno_manager;
mod trace_comparison;
mod transaction_simulator;
mod transaction_tracer;

use crate::cli::{Cli, Commands};
use crate::io::{
    base_trace_path, crashed_comparison_path, log_base_trace, log_comparison_report,
    log_crash_report, log_unexpected_error_report, read_base_trace, succesful_comparison_path,
};
use block_tracer::BlockTracer;
use cache::get_sorted_blocks_with_tx_count;
use chrono::Local;
use clap::Parser;
use core::panic;
use dependencies::simulation_report_dependencies;
use env_logger::Env;
use io::prepare_directories;
use juno_manager::{JunoBranch, JunoManager, ManagerError};
use log::{error, info, warn};
use starknet::core::types::SimulationFlag;
use std::io::Write;
use trace_comparison::generate_block_comparison;
use transaction_simulator::{SimulationStrategy, TransactionSimulator};
use transaction_tracer::TraceResult;

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

async fn execute_traces(
    start_block: u64,
    end_block: u64,
    redo_comparison: bool,
    redo_traces: bool,
    simulation_flags: Vec<SimulationFlag>,
) -> Result<(), ManagerError> {
    let mut base_juno = JunoManager::new(JunoBranch::Base).await?;
    let blocks_with_tx_count =
        get_sorted_blocks_with_tx_count(&mut base_juno, start_block, end_block)
            .await
            .unwrap();

    for (block_number, tx_count) in blocks_with_tx_count {
        if !redo_comparison
            && (succesful_comparison_path(block_number).exists()
                || crashed_comparison_path(block_number).exists())
        {
            info!("Skipping comparison for block {block_number} because it's already logged (use --redo-comp to do anyways)");
            continue;
        }

        info!("TRACING block {block_number} with Base. It has {tx_count} transactions");
        let using_cached_trace = !redo_traces && base_trace_path(block_number).exists();
        let base_trace_result = if !using_cached_trace {
            base_juno.trace_block(block_number).await
        } else {
            Ok(read_base_trace(block_number).await)
        };

        // First branch is a succesful block trace with Base
        // Second branch is an unexpected crash by Juno/Blockifier/nNative
        match base_trace_result {
            Ok(base_report) => {
                if base_report.result != TraceResult::Success {
                    // todo: prettier handling, but low prio.
                    let trace = serde_json::to_string_pretty(&base_report)
                        .unwrap_or(format!("Serialization failed!\n{base_report:?}"));
                    panic!("Tracing with base juno is always expected to work. Check your base juno bin and config. Error:\n{}",trace);
                }
                if !using_cached_trace {
                    log_base_trace(block_number, &base_report).await;
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
                        if let Err(e) = graph::write_transaction_dependencies(
                            block_number,
                            "native",
                            native_report.post_response.as_ref().unwrap().iter(),
                        ) {
                            warn!("Error writing transaction dependencies: {e:?}");
                        }
                        let comparison = generate_block_comparison(base_report, native_report);
                        log_comparison_report(block_number, comparison).await;
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
                                let reports_with_dependencies =
                                    simulation_report_dependencies(&result);
                                log_crash_report(block_number, reports_with_dependencies);
                            }
                            Err(err) => error!("Error simulating transactions: {}", err),
                        };
                    }
                    Err(err) => {
                        warn!("{err:?}");
                        log_unexpected_error_report(block_number, err).await;
                    }
                };
            }
            Err(err) => {
                warn!("{err:?}");
                log_unexpected_error_report(block_number, err).await;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), ManagerError> {
    setup_env_logger();
    prepare_directories().await;

    let cli = Cli::parse();

    let redo_comparison = cli.redo_comp;

    let redo_base_trace = cli.redo_base_trace;

    let mut simulation_flags = vec![];

    if cli.skip_validate {
        info!("Running a simulation with SKIP_VALIDATE flag");
        simulation_flags.push(SimulationFlag::SkipValidate)
    }

    if cli.skip_fee_charge {
        info!("Running a simulation with SKIP_FEE_CHARGE flag");
        simulation_flags.push(SimulationFlag::SkipFeeCharge)
    }

    let (start_block, end_block) = match cli.command {
        Commands::Block { block_num } => {
            let start_block = block_num;
            let end_block = block_num + 1;
            (start_block, end_block)
        }
        Commands::Range {
            start_block_num,
            end_block_num,
        } => (start_block_num, end_block_num),
    };

    // Note [Terminating Juno]
    // Pressing ctrl+c will cause the ctrl_c future to finish first and will abort execute_traces.
    // This will lead to the JunoManager's drop to be called which in turn issues a SIGKILL to Juno.
    // For now the native blockifier requires a SIGKILL to be terminated as it doesn't respond to SIGTERM in a timely manner.
    tokio::select! {
        _sigterm = tokio::signal::ctrl_c() => Ok(()),
        trace = execute_traces( start_block, end_block, redo_comparison, redo_base_trace, simulation_flags ) => trace,
    }
}
