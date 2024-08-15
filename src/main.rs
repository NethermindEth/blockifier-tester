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
    crashed_comparison_path, log_base_trace, log_comparison_report, log_crash_report,
    log_unexpected_error_report, read_base_trace, succesful_comparison_path,
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
use starknet::core::types::{SimulationFlag, TransactionTraceWithHash};
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

        let mut base_trace_result =
            trace_base(redo_traces, block_number, tx_count, &mut base_juno).await?;

        info!("Switching from Base Juno to Native Juno");
        base_juno.ensure_dead().await?;

        info!("TRACING block {block_number} with Native. It has {tx_count} transactions");
        let native_trace = trace_native(block_number, tx_count, &simulation_flags).await?;

        if let Some(mut native_trace) = native_trace {
            let comparison =
                generate_block_comparison(block_number, &mut base_trace_result, &mut native_trace);
            log_comparison_report(block_number, comparison).await;
        }
    }

    Ok(())
}

/// Traces a transaction using base Juno and caches to result to disk.
///
/// trace_base will try and read a valid cache from [`io::base_trace_path`] if it exists
/// otherwise it will trace a block using base Juno.
///
/// To force redoing a trace with base Juno set redo_traces to `true`.
async fn trace_base(
    redo_traces: bool,
    block_number: u64,
    tx_count: u64,
    base_juno: &mut JunoManager,
) -> Result<Vec<TransactionTraceWithHash>, ManagerError> {
    info!("TRACING block {block_number} with Base. It has {tx_count} transactions");

    let base_trace = match redo_traces {
        true => None,
        false => read_base_trace(block_number),
    };

    match base_trace {
        Some(trace) => {
            info!("Using cached trace for block {block_number}");
            Ok(trace)
        }
        None => {
            let base_trace_result = base_juno.trace_block(block_number).await;

            // todo(xrvdg) can we lift this out when reworking error?
            let base_trace_result = match base_trace_result {
                Ok(b) => Ok(b),
                Err(err) => {
                    warn!("{err:?}");
                    log_unexpected_error_report(block_number, &err).await;
                    Err(err)
                }
            }?;

            match base_trace_result.result {
                TraceResult::Success(trace) => {
                    log_base_trace(block_number, &trace);
                    Ok(trace)
                }

                base_report => {
                    // todo: prettier handling, but low prio.
                    let trace = serde_json::to_string_pretty(&base_report)
                        .unwrap_or(format!("Serialization failed!\n{base_report:?}"));

                    // todo(xrvdg) remove this panic when moving to parallel execution
                    panic!("Tracing with base juno is always expected to work. Check your base juno bin and config. Error:\n{}",trace);
                }
            }
        }
    }
}

async fn trace_native(
    block_number: u64,
    tx_count: u64,
    simulation_flags: &[SimulationFlag],
) -> Result<Option<Vec<TransactionTraceWithHash>>, ManagerError> {
    let mut native_juno = JunoManager::new(JunoBranch::Native).await?;

    let native_trace_result = native_juno.trace_block(block_number).await;

    // todo(xrvdg) can we lift this out when reworking error?
    let native_trace_result = match native_trace_result {
        Ok(b) => Ok(b),
        Err(err) => {
            warn!("{err:?}");
            log_unexpected_error_report(block_number, &err).await;
            Err(err)
        }
    }?;

    match native_trace_result.result {
        TraceResult::Success(native_trace) => {
            info!("SUCCESS tracing block with native");
            if let Err(e) =
                graph::write_transaction_dependencies(block_number, "native", native_trace.iter())
            {
                warn!("Error writing transaction dependencies: {e:?}");
            }
            Ok(Some(native_trace))
        }
        native_report => {
            // When tracing a block with native fails, the next step is performing a
            // binary search over the transactions searching for the one that crashes
            info!("Failed to trace block with Native, got {native_report:?}");
            info!("SIMULATING block {block_number} with Native. It has {tx_count} transactions");

            // We make sure Native Juno get properly killed before proceeding.
            native_juno.ensure_dead().await?;
            native_juno.ensure_usable().await?;
            let result = native_juno
                .simulate_block(block_number, SimulationStrategy::Binary, simulation_flags)
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
                    let reports_with_dependencies = simulation_report_dependencies(&result);
                    log_crash_report(block_number, reports_with_dependencies);
                }
                Err(err) => error!("Error simulating transactions: {}", err),
            };
            Ok(None)
        }
    }
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
        sigterm = tokio::signal::ctrl_c() => sigterm.map_err(|e| e.into()),
        trace = execute_traces( start_block, end_block, redo_comparison, redo_base_trace, simulation_flags ) => trace,
    }
}
