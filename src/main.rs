mod block_tracer;
mod cache;
mod cli;
mod dependencies;
mod gather_classes;
mod graph;
mod io;
mod juno_manager;
mod trace_comparison;
mod transaction_simulator;
mod transaction_tracer;
mod utils;

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
use io::{config_path, prepare_directories};
use juno_manager::{Config, JunoBranch, JunoManager, ManagerError, Network};
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
    network: Network,
    redo_comparison: bool,
    redo_traces: bool,
    skip_simulation: bool,
    simulation_flags: Vec<SimulationFlag>,
) -> Result<(), ManagerError> {
    let config = Config::from_path(&config_path())
        .map_err(|e| ManagerError::Internal(format!("Failed to load config: '{e:?}'")))?;

    let mut base_juno = JunoManager::new(JunoBranch::Base, config.clone(), network).await;
    base_juno.start_juno().await?;

    let blocks_with_tx_count =
        get_sorted_blocks_with_tx_count(&mut base_juno, start_block, end_block)
            .await
            .unwrap();

    let mut native_juno = JunoManager::new(JunoBranch::Native, config, network).await;
    for (block_number, tx_count) in blocks_with_tx_count {
        if !redo_comparison
            && (succesful_comparison_path(block_number, network).exists()
                || crashed_comparison_path(block_number, network).exists())
        {
            info!("Skipping comparison for block {block_number} because it's already logged (use --redo-comp to do anyways)");
            continue;
        }

        base_juno.start_juno().await?;
        let base_trace_result =
            trace_base(redo_traces, block_number, tx_count, &mut base_juno).await?;
        base_juno.stop_juno().await?;

        info!("Switching from Base Juno to Native Juno");

        native_juno.start_juno().await?;
        info!("TRACING block {block_number} with Native. It has {tx_count} transactions");
        let native_trace = trace_native(
            block_number,
            tx_count,
            &mut native_juno,
            skip_simulation,
            &simulation_flags,
        )
        .await?;
        native_juno.stop_juno().await?;

        if let Some(native_trace) = native_trace {
            match generate_block_comparison(block_number, base_trace_result, native_trace) {
                Ok(comparison) => log_comparison_report(block_number, network, comparison).await,
                Err(err) => {
                    warn!("Error generating block comparison for block {block_number}: {err}")
                }
            }
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

    let network = base_juno.network;
    let base_trace = if redo_traces {
        None
    } else {
        read_base_trace(block_number, network)
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
                    log_unexpected_error_report(block_number, network, &err).await;
                    Err(err)
                }
            }?;

            match base_trace_result.result {
                TraceResult::Success(trace) => {
                    log_base_trace(block_number, network, &trace);
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
    native_juno: &mut JunoManager,
    skip_simulation: bool,
    simulation_flags: &[SimulationFlag],
) -> Result<Option<Vec<TransactionTraceWithHash>>, ManagerError> {
    let native_trace_result = native_juno.trace_block(block_number).await;

    let network = native_juno.network;

    // todo(xrvdg) can we lift this out when reworking error?
    let native_trace_result = match native_trace_result {
        Ok(b) => Ok(b),
        Err(err) => {
            warn!("{err:?}");
            log_unexpected_error_report(block_number, network, &err).await;
            Err(err)
        }
    }?;

    match native_trace_result.result {
        TraceResult::Success(native_trace) => {
            info!("SUCCESS tracing block with native");
            if let Err(e) = graph::write_transaction_dependencies(
                block_number,
                network,
                "native",
                native_trace.iter(),
            ) {
                warn!("Error writing transaction dependencies: {e:?}");
            }
            Ok(Some(native_trace))
        }
        native_report if !skip_simulation => {
            // When tracing a block with native fails, the next step is performing a
            // binary search over the transactions searching for the one that crashes
            info!("Failed to trace block with Native, got {native_report:?}");
            info!("SIMULATING block {block_number} with Native. It has {tx_count} transactions");

            // We make sure Native Juno get properly killed before proceeding.
            native_juno.stop_juno().await?;
            native_juno.start_juno().await?;
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
                    log_crash_report(block_number, network, reports_with_dependencies);
                }
                Err(err) => error!("Error simulating transactions: {}", err),
            };
            Ok(None)
        }
        _ => Ok(None),
    }
}

#[tokio::main]
async fn main() -> Result<(), ManagerError> {
    setup_env_logger();
    prepare_directories().await;

    let cli = Cli::parse();

    let redo_comparison = cli.redo_comp;

    let redo_base_trace = cli.redo_base_trace;

    let skip_simulation = cli.skip_crash_simulation;

    let network = match cli.network.as_deref() {
        Some("mainnet") | None => Network::Mainnet,
        Some("sepolia") => Network::Sepolia,
        Some(other) => panic!("invalid network as argument: {other}"),
    };

    let mut simulation_flags = vec![];
    if cli.skip_validate {
        info!("Running a simulation with SKIP_VALIDATE flag");
        simulation_flags.push(SimulationFlag::SkipValidate)
    }
    if cli.skip_fee_charge {
        info!("Running a simulation with SKIP_FEE_CHARGE flag");
        simulation_flags.push(SimulationFlag::SkipFeeCharge)
    }

    // Note [Terminating Juno]
    // Pressing ctrl+c will cause the ctrl_c future to finish first and will abort execute_traces.
    // This will lead to the JunoManager's drop to be called which in turn issues a SIGKILL to Juno.
    // For now the native blockifier requires a SIGKILL to be terminated as it doesn't respond to SIGTERM in a timely manner.
    match cli.command {
        Commands::Block { block_num } => {
            tokio::select! {
            sigterm = tokio::signal::ctrl_c() => sigterm.map_err(|e| e.into()),
            trace =
                    execute_traces(
                        block_num,
                        block_num + 1,
                        network,
                        redo_comparison,
                        redo_base_trace,
                        skip_simulation,
                        simulation_flags,
                    ) => trace
                  }
        }

        Commands::Range {
            start_block_num,
            end_block_num,
        } => {
            tokio::select! {
            sigterm = tokio::signal::ctrl_c() => sigterm.map_err(|e| e.into()),
             trace =
                    execute_traces(
                        start_block_num,
                        end_block_num,
                        network,
                        redo_comparison,
                        redo_base_trace,
                        skip_simulation,
                        simulation_flags,
                    )
                    => trace
                  }
        }

        Commands::GatherClassHashes {} => {
            if redo_base_trace || redo_comparison {
                // todo: Handle re-tracing before gathering classes or remove flags from this subcommand.
                panic!("Not supported");
            }
            // todo: Handle tracing blocks before gathering classes to ensure all comparison files exist or optionally skip.
            tokio::select! {
                sigterm = tokio::signal::ctrl_c() => sigterm.map_err(|e| e.into()),
                gather =
                        gather_classes::gather_class_hashes(network)
                        => gather
            }
        }
    }
}
