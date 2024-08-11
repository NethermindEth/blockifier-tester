// Contains functions for the gather-class-hashes sub command.

// TODO (#72) Make async.

use crate::{
    io::{
        self, block_num_from_path, deserialize_or, path_for_overall_report, path_for_report, try_deserialize_or, try_serialize,
    },
    juno_manager::ManagerError,
    utils::{self, felt_to_hex, val_or_err},
};

use glob::glob;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::trace_comparison::{DIFFERENT, SAME};

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use itertools::Itertools;
use starknet::core::types::FieldElement;
use std::fs::OpenOptions;


use serde_json::Value;

type Count = usize;
/// Value for `entry_point_selector` key.
type EntryPoint = FieldElement;
/// Value for `class_hash` key.
type ClassHash = FieldElement;
/// Table of EntryPoint -> Number of occurrences.
type SelectorTable = HashMap<EntryPoint, Count>;

#[derive(Serialize, Deserialize)]
struct ClassHashesReport {
    report: HashMap<ClassHash, SelectorTable>,
    totals: HashMap<ClassHash, Count>,
    /// Blocks included in this report.
    blocks: HashSet<u64>,
}

impl ClassHashesReport {
    fn new() -> Self {
        Self {
            report: HashMap::<ClassHash, SelectorTable>::new(),
            totals: HashMap::<ClassHash, Count>::new(),
            blocks: HashSet::new(),
        }
    }

    /// Returns the number of counts added or an error.
    fn update(&mut self, report: &ClassHashesReport) -> Result<usize, anyhow::Error> {
        let new_blocks_len = report.blocks.union(&self.blocks).count();
        if new_blocks_len != self.blocks.len() + report.blocks.len() {
            // Reports may only be updated from reports with entirely different blocks.
            return Err(anyhow!("Reports contained overlapping blocks"));
        }

        let mut updates = 0;
        for (class_hash, table) in &report.report {
            for (entry_point, count) in table {
                self.update_count(*class_hash, *entry_point, *count);
                updates += count;
            }
        }
        self.blocks.extend(report.blocks.iter());
        Ok(updates)
    }

    fn update_count(&mut self, class_hash: ClassHash, entry_point: EntryPoint, count: usize) {
        let entry = self.report.entry(class_hash).or_default();
        let table_entry = entry.entry(entry_point).or_insert(0);
        *table_entry += count;

        let totals_entry = self.totals.entry(class_hash).or_insert(0);
        *totals_entry += count;
    }

    fn add_fields(&mut self, class_hash: ClassHash, entry_point: EntryPoint) {
        self.update_count(class_hash, entry_point, 1)
    }
}

impl core::fmt::Display for ClassHashesReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map_vec = self.report.iter().collect_vec();
        map_vec.sort_by(|(class_hash_a, _table_a), (class_hash_b, _table_b)| {
            let count_a = self.totals[class_hash_a];
            let count_b = self.totals[class_hash_b];
            count_a.cmp(&count_b)
        });

        for (class_hash, table) in map_vec {
            f.write_fmt(format_args!(
                "class_hash: {}\tTotal: {}\n",
                utils::felt_to_hex(class_hash, true),
                self.totals[class_hash]
            ))?;
            let mut table_vec = table.iter().collect_vec();
            table_vec.sort_by(|(entry_point_a, count_a), (entry_point_b, count_b)| {
                match count_a.cmp(count_b) {
                    Ordering::Less => Ordering::Less,
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Equal => entry_point_a.cmp(entry_point_b),
                }
            });

            f.write_fmt(format_args!("\t{: <70}\tCount\n", "Selector"))?;
            for (entry_point, count) in table_vec {
                f.write_fmt(format_args!(
                    "\t{}\t{}\n",
                    felt_to_hex(entry_point, true),
                    count
                ))?;
            }
        }
        Ok(())
    }
}

/// Scans the `./results` folder for block comparisons and updates class_hashes report.
pub async fn gather_class_hashes() -> Result<(), ManagerError> {
    let force_generate = false;
    let mut overall_report =
        deserialize_or(&path_for_overall_report(), ClassHashesReport::new);

    let compare_paths = get_comparison_blocks()
        .into_iter()
        .filter(|(block_num, _path)| !overall_report.blocks.contains(block_num))
        .collect_vec();
    info!("New blocks to add: {}", compare_paths.len());
    process_compare_paths(&mut overall_report, compare_paths, force_generate);

    info!("{overall_report}");

    info!("Serializing...");
    try_serialize(path_for_overall_report(), &overall_report)
        .map_err(|err| ManagerError::Internal(format!("{err:?}")))
}

/// Returns Vec<block_num, comparison_file_path> for each results/comparison-*.json.
fn get_comparison_blocks() -> Vec<(u64, PathBuf)> {
    let results_glob = io::successful_comparison_glob();
    let (errors, mut paths): (Vec<_>, Vec<_>) = glob(results_glob.as_str())
        .expect("Failed to glob comparison results.")
        .partition_map(From::from);
    paths.sort_unstable();
    info!(
        "Globbed {} files.\tEncountered {} errors.",
        paths.len(),
        errors.len()
    );

    paths
        .into_iter()
        .map(|path| {
            let block_num = block_num_from_path(path.as_path()).unwrap_or_else(|_| panic!("Failed to get block_num from path: `{}`",
                    path.to_str().unwrap()));
            (block_num, path)
        })
        .collect_vec()
}

/// Updates overall_report to include data from block reports.
/// Side effects: Creates reports for each block read from each path in `file_paths` if they do not already exist.
/// `force_generate` : If false, attempts to deserialize reports instead of generating them, otherwise always generates block reports.
///
/// Params: `file_paths` Vector of (block_num, file_path).
fn process_compare_paths(
    overall_report: &mut ClassHashesReport,
    file_paths: Vec<(u64, PathBuf)>,
    force_generate: bool,
) {
    if file_paths.is_empty() {
        return;
    }

    let total = file_paths.len();
    let get_stat = |prefix, value| {
        format!(
            "{prefix}: {value}/{} ({:.2}%)",
            total,
            100.00 * ((value as f64) / (total as f64)),
        )
    };
    let mut failures = 0;
    let mut processed = 0;

    // TODO (#72) Potential speedup: Process each file with `Process(path) -> ClassHashesReport` in parallel, then merge ClassHashesReport together.
    for (block_num, path) in file_paths.into_iter() {
        info!(
            "{}\t{}\t{}",
            get_stat("Processed", processed),
            get_stat("Successes", processed - failures),
            get_stat("Failures", failures)
        );
        info!(
            "Processing path: `{}`",
            path.file_name().unwrap().to_str().unwrap()
        );

        let maybe_block_report = match force_generate {
            false => try_deserialize_or(&path_for_report(block_num), || generate_report(&path)),
            true => generate_report(&path),
        };

        match maybe_block_report {
            Err(err) => {
                warn!("Failed to process file with err: {err}");
                failures += 1;
            }
            Ok(block_report) => {
                let _ = try_serialize_block_report(block_num, &block_report, force_generate)
                    .map_err(|err| warn!("{err:?}"));
                processed += 1;

                let update_result = overall_report.update(&block_report);
                match update_result {
                    Err(err) => {
                        info!("{err}");
                        failures += 1;
                    }
                    Ok(updates) => {
                        info!("Updates to overall report from block {block_num}: {updates}");
                        let _ = try_serialize(path_for_overall_report(), &overall_report)
                            .inspect_err(|err| warn!("{err}"));
                    }
                }
            }
        }
    }
    info!(
        "{}\t{}\t{}",
        get_stat("Processed", processed),
        get_stat("Successes", processed - failures),
        get_stat("Failures", failures)
    );
}

fn generate_report<P>(path: P) -> Result<ClassHashesReport, anyhow::Error>
where
    P: AsRef<Path>,
{
    let path_str = path.as_ref().to_str().expect("failed to unwrap path");

    let mut comparison_file = OpenOptions::new()
        .read(true)
        .open(path.as_ref())
        .context(format!("Reading comparison file: '{}'", path_str,))
        .inspect_err(|err| {
            warn!("Error reading file: {err}");
        })?;

    let mut data = String::new();
    let _data_len = comparison_file.read_to_string(&mut data)?;
    let json_obj: Value = serde_json::from_str(data.as_str()).expect("unwrapping json_obj");

    let json_block_num = block_num_from_json(&json_obj);
    let path_block_num = block_num_from_path(path_str);
    let block_num = val_or_err(path_block_num, json_block_num)?;

    let mut report = ClassHashesReport::new();
    update_report(&mut report, &json_obj, block_num)?;
    assert!(report.blocks.len() == 1 && report.blocks.contains(&block_num));
    Ok(report)
}

/// Returns: Either `Some(updates)` where `updates` is the number of updates made to the report or an Error.
fn update_report(
    report: &mut ClassHashesReport,
    obj: &Value,
    block_num: u64,
) -> Result<usize, anyhow::Error> {
    if let Value::String(same) = obj {
        // TODO (#72) Rethink handling this.
        debug!("File only has a string object. It should be \"same\": `{obj}`");
        assert!(same == &format!("{}({{{}}}))", SAME, block_num));
        warn!("This is not expected. Execution resources should differ.");
        return Err(anyhow!("Native and Base were the same."));
    }

    if report.blocks.contains(&block_num) {
        return Err(
            anyhow!("Report already contains block").context(format!("block_num: {block_num}"))
        );
    }

    let mut updates = 0;
    for transaction in obj["post_response"].as_array().expect("expected array") {
        let root_call = &transaction["trace_root"]["execute_invocation"];
        if let Value::Null = root_call {
            // Most likely, this "trace_root" has no "execute_invocation".
            debug!("skipping transaction: `{transaction}`");
            continue;
        }
        for call in get_calls(root_call) {
            let maybe_kvp = get_tuple_from_call(call);
            match maybe_kvp {
                Ok(kvp) => {
                    report.add_fields(kvp.1, kvp.0);
                    updates += 1;
                }
                Err(err) => {
                    debug!("Failed to extract tuple with error: {err}");
                }
            }
        }
    }
    assert!(report.blocks.insert(block_num));
    Ok(updates)
}

// Converts recursive calls to value.get("calls") to a boxed iterator.
fn get_calls<'a>(obj: &'a Value) -> Box<dyn Iterator<Item = &Value> + 'a> {
    // TODO (#72) Put debug logging here under a core::option_env flag so it is normally hidden.
    match obj {
        Value::String(_same) => Box::new(::std::iter::empty()),
        Value::Array(call_list) => {
            let nested_calls = call_list
                .iter()
                .flat_map(|inner_call| get_calls(inner_call));
            Box::new(call_list.iter().chain(nested_calls))
        }
        Value::Object(obj_map) => {
            if let Some(Value::Object(diff_map)) = obj_map.get(DIFFERENT) {
                let base_list = diff_map.get("base").expect("difference should have base");
                let native_list = diff_map
                    .get("native")
                    .expect("difference should have native");
                // TODO (#72) Compare and get diffs. For now we just chain.
                Box::new(get_calls(base_list).chain(get_calls(native_list)))
            } else if let Some(calls_value) = obj_map.get("calls") {
                get_calls(calls_value)
            } else if let Some(_val) = obj_map.get("revert_reason") {
                Box::new(::std::iter::empty())
            } else {
                // TODO (#72) Handle errors gracefully.
                warn!("unexpected: `{}`", obj);
                panic!();
            }
        }
        // TODO (#72) Handle errors gracefully.
        _ => panic!("unexpected!"),
    }
}

/// returns `Result<(EntryPoint, ClassHash), anyhow::Error>`
fn get_tuple_from_call(call: &Value) -> Result<(EntryPoint, ClassHash), anyhow::Error> {
    let mut values = Vec::<FieldElement>::new();
    for key in ["entry_point_selector", "class_hash"] {
        let next = call
            .get(key)
            .context(format!("call: `{call}`\n-------Extracting key {key}"))?;
        let felt_version = serde_json::from_value(next.clone())
            .context(format!("convert value `{}` to felt", next))?;
        values.push(felt_version);
    }
    Ok((values[0], values[1]))
}

/// Checks that the report corresponds to the block_num.
/// Then, if no report exists or `overwrite` is `true`, tries to serialize the report.
fn try_serialize_block_report(
    block_num: u64,
    report: &ClassHashesReport,
    overwrite: bool,
) -> Result<(), anyhow::Error> {
    assert!(report.blocks.len() == 1 && report.blocks.contains(&block_num));

    let report_path = path_for_report(block_num);
    if overwrite || !report_path.exists() {
        try_serialize(path_for_report(block_num), report).context(format!("block_num: {block_num}"))
    } else {
        Err(anyhow!("Skipped"))
    }
}

fn block_num_from_json(obj: &Value) -> Result<u64, anyhow::Error> {
    let re = regex::Regex::new(r"Same\((?<inner>.*?)\)").unwrap();
    match obj.get("block_num") {
        Some(Value::String(block_string)) => {
            match re.captures(block_string).map(|caps| caps.name("inner")) {
                Some(Some(inner_match)) => inner_match
                    .as_str()
                    .parse::<u64>()
                    .context("Convert match to u64."),
                _ => Err(anyhow!("Failed to match regex for block_num.")),
            }
        }
        Some(Value::Number(block_num)) => match block_num.as_u64() {
            None => Err(anyhow!(
                "Failed to convert block_num from json Value::Number."
            )),
            Some(block) => Ok(block),
        },
        _ => Err(anyhow!("Failed to get block_num from json object.")),
    }
}
