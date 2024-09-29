use anyhow::{anyhow, Context};
use futures::future;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use starknet::core::types::TransactionTraceWithHash;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use tokio::{
    fs::OpenOptions as AsyncOpenOptions,
    io::{AsyncWriteExt, BufWriter},
};

use log::{debug, info, warn};

use crate::juno_manager::{ManagerError, Network};

pub fn block_num_from_path<P>(path: P) -> Result<u64, anyhow::Error>
where
    P: AsRef<Path>,
{
    let path_str = path.as_ref().to_str().unwrap_or("Failed to get path str");
    let context = format!("path: `{path_str}`");

    let file_name = path
        .as_ref()
        .file_name()
        .context(context.clone())?
        .to_str()
        .context(context.clone())?;
    let re = regex::Regex::new(r"(.*?)-(?<block_num>\d+).json").expect("Unwrapping regex.");
    let caps = re.captures(file_name).context(context.clone())?;
    let block_match = caps.name("block_num").context(context.clone())?;
    block_match.as_str().parse::<u64>().context(context)
}

pub fn cache_path(network: Network) -> PathBuf {
    PathBuf::from(format!("./cache/{}_block_tx_counts", network))
}

pub fn config_path() -> PathBuf {
    PathBuf::from("./config.toml")
}

pub fn path_for_overall_report(network: Network) -> PathBuf {
    PathBuf::from(format!(
        "results-{}/class_hashes/overall_report.json",
        network
    ))
}

pub fn successful_comparison_glob(network: Network) -> String {
    format!("results-{}/comparison-*.json", network)
}

pub fn trimmed_comparison_path(block_num: u64, network: Network) -> PathBuf {
    PathBuf::from(format!(
        "results-{network}/comparison-{block_num}-trimmed.json",
    ))
}

pub fn succesful_comparison_path(block_num: u64, network: Network) -> PathBuf {
    PathBuf::from(format!("results-{}/comparison-{}.json", network, block_num))
}

pub fn crashed_comparison_path(block_num: u64, network: Network) -> PathBuf {
    PathBuf::from(format!("results-{}/crash-{}.json", network, block_num))
}

pub fn unexpected_error_comparison_path(block_num: u64, network: Network) -> PathBuf {
    PathBuf::from(format!(
        "results-{}/unexpected-error-{}.json",
        network, block_num
    ))
}

pub fn base_trace_path(block_num: u64, network: Network) -> PathBuf {
    PathBuf::from(format!("results-{network}/base/trace-{}.json", block_num))
}

// Creates a file in ./results/trace-{`block_number`}.json with the a full trace comparison between
// base blockifier and native blockifier results
pub async fn log_comparison_report(block_number: u64, network: Network, comparison: Value) {
    let mut buffer = Vec::new();
    serde_json::to_writer_pretty(&mut buffer, &comparison).unwrap();

    let log_file = AsyncOpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(succesful_comparison_path(block_number, network))
        .await
        .expect("Failed to open log file");

    let mut writer = BufWriter::new(log_file);
    writer.write_all(&buffer).await.unwrap();
    writer.flush().await.unwrap();
}

pub fn log_crash_report(block_number: u64, network: Network, report: serde_json::Value) {
    info!("Log report for block {block_number}");
    let block_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(crashed_comparison_path(block_number, network))
        .expect("Failed to open log file");

    serde_json::to_writer_pretty(block_file, &report)
        .unwrap_or_else(|_| panic!("failed to write block: {block_number}"));
}

// Creates a file in ./results/crash-{`block_number`}.json with the failure reason
pub async fn log_unexpected_error_report(block_number: u64, network: Network, err: &ManagerError) {
    let mut log_file = AsyncOpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(unexpected_error_comparison_path(block_number, network))
        .await
        .expect("Failed to open log file");
    if let Err(write_err) = log_file.write_all(format!("{err:?}").as_bytes()).await {
        warn!("Failed to write err with error: '{write_err}'");
    }
}

// Creates a file in ./results/base/trace-{`block_number`}.json with the block trace by Base Juno
pub fn log_base_trace(block_number: u64, network: Network, trace: &Vec<TransactionTraceWithHash>) {
    info!("Log trace for block {block_number}");

    let block_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(base_trace_path(block_number, network))
        .expect("Failed to open log file");

    serde_json::to_writer_pretty(block_file, trace)
        .unwrap_or_else(|_| panic!("failed to write block: {block_number}"));
}

/// Read a cached base trace
///
/// Returns None if no valid cached base trace is found.
/// todo(xrvdg) convert to result once blockifier has been parallelized?
pub fn read_base_trace(
    block_number: u64,
    network: Network,
) -> Option<Vec<TransactionTraceWithHash>> {
    let block_file = OpenOptions::new()
        .read(true)
        .open(base_trace_path(block_number, network))
        .ok()?;

    // If parsing fails the file format has changed and the cache is invalidated
    serde_json::from_reader(block_file).ok()?
}

pub async fn prepare_directories() {
    debug!("Preparing directories");
    let paths = [
        |_| format!("./cache"),
        |net| format!("./results-{net}"),
        |net| format!("./results-{net}/base"),
        |net| format!("./results-{net}/native"),
        |net| format!("./results-{net}/dependencies"),
        |net| format!("./results-{net}/class_hashes"),
    ]
    .into_iter()
    .flat_map(|f| [f(Network::Mainnet), f(Network::Sepolia)]);

    future::join_all(paths.map(tokio::fs::create_dir_all)).await;
}

pub fn try_deserialize<T, P>(path: P) -> Result<T, anyhow::Error>
where
    T: for<'a> Deserialize<'a>,
    P: AsRef<Path>,
{
    let path_str = path.as_ref().to_str().unwrap_or("<Failed to unwrap path.>");

    if !path.as_ref().exists() {
        return Err(anyhow!("Path does not exist: {}", path_str));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path.as_ref())
        .context(format!("Opening file: {}", path_str))?;
    serde_json::from_reader(file).context(format!("Deserializing from file: {}", path_str))
}

/// Attempts to serialize `obj` to `path`.
pub fn try_serialize<T, P>(path: P, obj: T) -> Result<(), anyhow::Error>
where
    T: Serialize,
    P: AsRef<Path>,
{
    let mut buffer = Vec::new();
    serde_json::to_writer_pretty(&mut buffer, &obj).unwrap();

    let path_str = path.as_ref().to_str().expect("failed to unwrap path");

    let mut out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path.as_ref())
        .context(format!("Reading path: '{path_str}'"))?;

    out_file
        .write_all(&buffer)
        .context(format!("Writing path: '{path_str}'"))
}
