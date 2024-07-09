use anyhow::Context;
use futures::Future;
use log::{debug, info};
use num_bigint::BigUint;
use starknet::core::types::FieldElement;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

pub async fn try_read_from_file<R>(path: &Path) -> Result<R, anyhow::Error>
where
    R: serde::de::DeserializeOwned,
{
    debug!("Trying to read from cache file: {}", path.to_str().unwrap());
    let mut cache_file = OpenOptions::new()
        .read(true)
        .open(path)
        .await
        .context(format!(
            "Reading cache file: '{}'",
            path.to_str().expect("failed to unwrap path")
        ))?;
    let mut data = Vec::<u8>::new();
    cache_file.read_to_end(&mut data).await?;
    debug!("Read from cache file: {}", path.to_str().unwrap());

    Ok(serde_json::from_slice(&data)?)
}

pub async fn try_write_to_file<T>(path: &Path, value: &T) -> Result<(), anyhow::Error>
where
    T: serde::ser::Serialize,
{
    debug!("Trying to write to cache file: {}", path.to_str().unwrap());
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .context(format!(
            "Writing to cache file: {}",
            path.to_str().expect("failed to unwrap path")
        ))?;
    let mut buffer = Vec::new();
    serde_json::to_writer_pretty(&mut buffer, &value).unwrap(); // todo: replace with ?
    let mut writer = BufWriter::new(log_file);
    writer.write_all(&buffer).await.unwrap();
    writer.flush().await?;
    debug!("Wrote to cache file: {}", path.to_str().unwrap());
    Ok(())
}

pub async fn memoized_call<R, F, F2>(cache_path: &Path, func: F) -> Result<R, anyhow::Error>
where
    F: FnOnce() -> F2,
    F2: Future<Output = Result<R, anyhow::Error>>,
    R: serde::de::DeserializeOwned + serde::ser::Serialize,
{
    debug!(
        "Running memoized call with path: {}",
        cache_path.to_str().unwrap()
    );
    let read_result = try_read_from_file::<R>(cache_path).await;
    match read_result {
        Ok(out) => Ok(out),
        Err(_err) => {
            debug!("Attempt to get cached object from cache file failed: {_err:?}");
            let result = func().await;
            if let Ok(value) = &result {
                let _ = try_write_to_file(cache_path, value)
                    .await
                    .inspect_err(|err| info!("Error writing to cache: {err:?}"));
            }
            result
        }
    }
}

pub fn felt_to_hex(value: &FieldElement, with_prefix: bool) -> String {
    match with_prefix {
        true => format!("0x{}", felt_to_hex(value, false)),
        false => BigUint::from_bytes_be(&value.to_bytes_be()).to_str_radix(16),
    }
}

// pub async fn do_stuff() {
//     let block_num = 4_u64;
//     let transactions = memoized_call("path", || async {
//         try_native_block_trace(block_num)
//             .await
//             .map_err(|err| anyhow::anyhow!(err))
//     })
//     .await;

//     match transactions {
//         Ok(transaction) => {
//             // We got the transaction.
//         }
//         Err(err) => {
//             // Our closure failed.
//         }
//     }
// }
