use std::{fs::OpenOptions, path::Path};

use anyhow::Context;
use log::{debug, info, warn};
use starknet::core::types::BlockId;

use crate::juno_manager::{JunoBranch, JunoManager, ManagerError};

/// returns a list of (block number, transaction count), sorted by ascending transaction count
/// draws from and updates ./cache/block_tx_counts if necessary
/// block_start: inclusive lower bound
/// block_end: exclusive upper bound
pub async fn get_sorted_blocks_with_tx_count(
    block_start: u64,
    block_end: u64,
) -> Result<Vec<(u64, u64)>, ManagerError> {
    let cache_path = Path::new("./cache/block_tx_counts");
    // First load the entire cache
    let cache_data = read_block_tx_counts_cache(cache_path);
    match &cache_data {
        Ok(data) => info!("Got cache with {} elements", data.len()),
        Err(err) => warn!("Got err {err}"),
    }
    // If no cache could be loaded, treat it as being empty
    let mut cache_data = cache_data.unwrap_or_default();
    // Sort the cache by block index to allow efficient searching
    cache_data.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    let mut result = vec![];
    let mut juno_manager = JunoManager::new(JunoBranch::Native)
        .await
        .expect("Failed to start native juno");

    // For each block, use its cached result if present, and if not then ask juno and add it to the cache data
    for block_num in block_start..block_end {
        debug!("Searching for {block_num} in cache");
        match cache_data.binary_search_by(|(x, _)| x.cmp(&block_num)) {
            Ok(idx) => result.push(cache_data[idx]),
            Err(idx) => {
                debug!("{block_num} not found in cache. get_block_transaction_count");
                let tx_count = juno_manager
                    .get_block_transaction_count(BlockId::Number(block_num))
                    .await?;
                result.push((block_num, tx_count));
                cache_data.insert(idx, (block_num, tx_count));
            }
        }
    }

    // Give juno a graceful shutdown period now that we're done with it
    juno_manager.ensure_dead().await?;

    // Write the data back to the cache, including any new results found from juno
    if let Err(err) = write_block_tx_counts_cache(cache_path, &cache_data).await {
        warn!(
            "Failed to write block_tx_counts to cache: '{}': '{}'",
            cache_path.to_str().expect("failed to unwrap cache_path"),
            err
        );
    }

    // Reorder the results by transaction count, so that we run smaller blocks first
    result.sort_by(|lhs, rhs| lhs.1.cmp(&rhs.1));
    debug!("Got blocks with transaction counts: {:?}", result);
    Ok(result)
}

fn read_block_tx_counts_cache(path: &Path) -> Result<Vec<(u64, u64)>, anyhow::Error> {
    let cache_file = OpenOptions::new().read(true).open(path).context(format!(
        "Reading cache file: '{}'",
        path.to_str().expect("failed to unwrap path")
    ))?;
    let reader = std::io::BufReader::new(cache_file);
    Ok(serde_json::from_reader(reader)?)
}

pub async fn write_block_tx_counts_cache(
    path: &Path,
    counts: &Vec<(u64, u64)>,
) -> Result<(), anyhow::Error> {
    tokio::fs::create_dir_all(path.parent().unwrap_or(path)).await?;
    let cache_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .append(false)
        .open(path)
        .context(format!(
            "Writing cache file: '{}'",
            path.to_str().expect("failed to unwrap path")
        ))?;
    let writer = std::io::BufWriter::new(cache_file);
    serde_json::to_writer(writer, &counts).context(format!(
        "Serializing to writer on path: '{}'",
        path.to_str().expect("failed to unwrap path")
    ))
}
