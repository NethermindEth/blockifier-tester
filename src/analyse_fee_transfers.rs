use crate::{
    gather_classes::get_comparison_blocks,
    io::path_for_fee_transfers,
    juno_manager::Network,
};

use std::{collections::HashMap, fs::OpenOptions};

use std::io::Write;

use crate::io;
use anyhow::{anyhow, Context};
use log::info;
use serde_json::Value;

enum KnownHash {
    ContractHash(&'static str),
    ClassHash(&'static str),
}
impl std::fmt::Display for KnownHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            KnownHash::ContractHash(label) => f.write_fmt(format_args!("Contract: '{label}'")),
            KnownHash::ClassHash(label) => f.write_fmt(format_args!("Class: '{label}'")),
        }
    }
}

fn known_hashes() -> HashMap<&'static str, KnownHash> {
    [
        (
            "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            KnownHash::ContractHash("StarkGate: ETH Token"),
        ),
        (
            "0x7f3777c99f3700505ea966676aac4a0d692c2a9f5e667f4c606b51ca1dd3420",
            KnownHash::ClassHash("StarkGate: ETH Token"),
        ),
        (
            "0x54aeaaae292062944e8f4bcd456618768a7277ffe1e80710d8d82064995686c",
            KnownHash::ContractHash("Braavos"),
        ),
        (
            "0x0816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253",
            KnownHash::ClassHash("Braavos"),
        ),
        (
            "0x3131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e",
            KnownHash::ClassHash("BraavosProxy (v0)"),
        ),
        (
            "0x5683a91297bc003a7a5931ff84d9f18065dbffd2370acc8559f17d0c32885bb",
            KnownHash::ContractHash("ArgentProxy (v0)"),
        ),
        (
            "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
            KnownHash::ClassHash("ArgentProxy (v0)"),
        ),
    ]
    .into()
}

fn get_labels_for_trace(block_trace: &Value, transaction_hash: &str) -> Vec<String> {
    for transaction in block_trace
        .as_array()
        .expect("Transactions should be an array")
    {
        let hash = transaction["transaction_hash"]
            .as_str()
            .expect("transaction_hash should be a string");
        if hash == transaction_hash {
            return get_hash_labels(transaction);
        }
    }
    vec![]
}

/// Get "class_hash" values from `call` and inner "calls".
/// Input structure:
/// {
///    "class_hash" : "0x1234" // Hash in string form.
///    "calls" : [] // A call may have more calls.
/// }
///
/// If `call` is not `obj`: panic!()
/// If `call` has no class_hash : Ignore, but continue recurse
/// etc. etc.
/// Returns: Iterable of `class_hash`s (&str with lifetime based on lifetime of `call`)
fn get_class_hashes<'a>(call: &'a Value) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    let obj = call.as_object().expect("calls should be objects");
    let class_hash = obj.get("class_hash").and_then(|h| h.as_str());
    let inner_calls = obj.get("calls").and_then(|inner| inner.as_array());
    let inner_hashes = match inner_calls {
        Some(calls) => calls
            .iter()
            .flat_map(|inner_call| get_class_hashes(inner_call)),
        None => todo!(),
    };
    Box::new(class_hash.into_iter().chain(inner_hashes))
}

fn get_hash_labels(transaction: &Value) -> Vec<String> {
    // Only look at the "execute_invocation" for accurate contract/class hashes that were called.
    let execution = &transaction["trace_root"]["execute_invocation"];

    let mut labels = vec![];

    match &execution["class_hash"] {
        Value::String(contract) => {
            if let Some(known_hash) = known_hashes().remove(contract.as_str()) {
                labels.push(format!("class_hash({known_hash})"));
            }
        }
        _ => {
             // ignore. maybe it was reverted
        }
    }

    if let Some(revert_reason) = &execution.get("revert_reason") { labels.push(format!("Reverted: `{revert_reason}`")) }

    match &execution["calls"] {
        Value::Array(calls) => {
            for call in calls {
                for call_class_hash in get_class_hashes(call) {
                    if let Some(known_hash) = known_hashes().remove(call_class_hash) {
                        labels.push(format!("ContainsCallTo({known_hash})"));
                    }
                }
            }
        }
        _ => {
             // Maybe it was reverted.
        }
    }

    labels
}

pub async fn analyse_transfer_fees(network: Network) -> Result<(), anyhow::Error> {
    let compare_paths = get_comparison_blocks(network);
    for (block, _path) in compare_paths {
        analyse_at_fee_transfers(block, network).await?
    }
    Ok(())
}

enum Row {
    Same {
        index: usize,
        transaction_hash: String,
        same_inner: String,
        labels: Vec<String>,
    },
    Different {
        index: usize,
        transaction_hash: String,
        labels: Vec<String>,
    },
}

impl std::fmt::Display for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Row::Same {
                index,
                transaction_hash,
                same_inner,
                labels,
            } => write!(
                f,
                "Same, {}, {}, {}, [{}]",
                index,
                transaction_hash,
                same_inner,
                labels.join(",")
            ),
            Row::Different {
                index,
                transaction_hash,
                labels,
            } => write!(
                f,
                "Different, {}, {},, [{}]",
                index,
                transaction_hash,
                labels.join(",")
            ),
        }
    }
}

fn fee_transfer_row(transaction: &Value, index: usize, native_trace: &Value) -> Row {
    match &transaction["trace_root"]["fee_transfer_invocation"] {
        Value::String(inner) => {
            let re = regex::Regex::new(r"Same\((?<same>.*)\)").unwrap();
            match re.captures(inner) {
                Some(caps) => {
                    let same_inner = caps.name("same").unwrap().as_str();
                    let transaction_hash = transaction["transaction_hash"].as_str().unwrap();
                    let labels = get_labels_for_trace(native_trace, transaction_hash);
                    Row::Same {
                        index,
                        transaction_hash: transaction_hash.to_string(),
                        same_inner: same_inner.to_string(),
                        labels,
                    }
                }
                None => panic!("not same"),
            }
        }
        _ => {
            let transaction_hash = transaction["transaction_hash"].as_str().unwrap();
            let labels = get_labels_for_trace(native_trace, transaction_hash);
            Row::Different {
                index,
                transaction_hash: transaction_hash.to_string(),
                labels,
            }
        }
    }
}

pub async fn analyse_at_fee_transfers(
    block_num: u64,
    network: Network,
) -> Result<(), anyhow::Error> {
    info!("Analyzing fee transfers for block {block_num}");
    let trace_path = io::base_trace_path(block_num, network);
    let trace: Value = io::try_deserialize(trace_path).unwrap();

    let path = io::succesful_comparison_path(block_num, network);
    let comparison: Value = io::try_deserialize(path).unwrap();

    let transactions = comparison["post_response"]
        .as_array()
        .ok_or(anyhow!("post_response was not an array."))?;

    let mut rows = vec![];
    let mut same_transactions = vec![];
    let mut diff_transactions = vec![];
    let mut index = 0;
    for transaction in transactions {
        let row = fee_transfer_row(transaction, index, &trace);
        match &row {
            Row::Same {
                index: _,
                transaction_hash: _,
                same_inner: _,
                labels: _,
            } => same_transactions.push((index, transaction)),
            Row::Different {
                index: _,
                transaction_hash: _,
                labels: _,
            } => diff_transactions.push((index, transaction)),
        }
        rows.push(row);
        index += 1;
    }

    serialize_rows(rows, block_num, network)
}

/// Serializes rows to fee_transfers out file.
/// First writes all the Same fee transfers, then all the Different ones.
fn serialize_rows(rows: Vec<Row>, block_num: u64, network: Network) -> Result<(), anyhow::Error> {
    let out_path = path_for_fee_transfers(network, block_num);
    let mut out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(false)
        .open(&out_path)
        .context(format!("Path: {}", out_path.to_str().unwrap()))?;
    writeln!(
        out_file,
        "Comparison, Index, Transaction Hash, Inner, Labels"
    )?;
    for row in &rows {
        if matches!(
            row,
            Row::Same {
                index: _,
                transaction_hash: _,
                same_inner: _,
                labels: _
            }
        ) {
            writeln!(out_file, "{}", row)?;
        }
    }

    for row in &rows {
        if matches!(
            row,
            Row::Different {
                index: _,
                transaction_hash: _,
                labels: _
            }
        ) {
            writeln!(out_file, "{}", row)?;
        }
    }

    Ok(())
}
