// Contains functions for the gather-class-hashes sub command.

// TODO (#72) Make async.

use crate::{
    io::{self, block_num_from_path, path_for_overall_report, try_deserialize, try_serialize},
    juno_manager::{ManagerError, Network},
    trace_comparison::string_is_same,
    utils::{self, felt_to_hex},
};

use glob::glob;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::trace_comparison::DIFFERENT;

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use anyhow::{anyhow, Context};
use itertools::Itertools;
use starknet::core::types::FieldElement;

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

    fn contains_block(&self, block_num: &u64) -> bool {
        self.blocks.contains(block_num)
    }

    #[allow(dead_code)]
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
        map_vec.sort_by(|(class_hash_a, _), (class_hash_b, _)| {
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
pub async fn gather_class_hashes(network: Network) -> Result<(), ManagerError> {
    let overall_report =
        try_deserialize(path_for_overall_report(network)).unwrap_or(ClassHashesReport::new());

    let compare_paths = get_comparison_blocks(network)
        .into_iter()
        .filter(|(block_num, _path)| !overall_report.contains_block(block_num))
        .collect_vec();
    info!("New blocks to add: {}", compare_paths.len());
    let overall_report = process_compare_paths(overall_report, compare_paths, network);

    info!("{overall_report}");

    info!("Serializing...");
    try_serialize(path_for_overall_report(network), &overall_report)
        .map_err(|err| ManagerError::Internal(format!("{err:?}")))
}

/// Returns Vec<block_num, comparison_file_path> for each results/comparison-*.json.
fn get_comparison_blocks(network: Network) -> Vec<(u64, PathBuf)> {
    let results_glob = io::successful_comparison_glob(network);
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
            let block_num = block_num_from_path(path.as_path())
                .context(format!("path: `{}`", path.to_str().unwrap()))
                .expect("Failed to get block_num from path.");
            (block_num, path)
        })
        .collect_vec()
}

/// Updates overall_report to include data from block reports.
///
/// Params: `file_paths` Vector of (block_num, file_path).
fn process_compare_paths(
    overall_report: ClassHashesReport,
    file_paths: Vec<(u64, PathBuf)>,
    network: Network,
) -> ClassHashesReport {
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

    let mut overall_report = overall_report;
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
        processed += 1;

        let json_result: Result<Value, _> = try_deserialize(path);
        if let Err(err) = json_result {
            warn!("Failed to process file with err: {err}");
            failures += 1;
            continue;
        }
        let json_obj = json_result.unwrap();

        let update_result = update_report(&mut overall_report, &json_obj, block_num);
        match update_result {
            Err(err) => {
                info!("{err}");
                failures += 1;
            }
            Ok(updates) => {
                info!("Updates to overall report from block {block_num}: {updates}");
                let _ = try_serialize(path_for_overall_report(network), &overall_report)
                    .inspect_err(|err| warn!("{err}"));
            }
        }
    }
    info!(
        "{}\t{}\t{}",
        get_stat("Processed", processed),
        get_stat("Successes", processed - failures),
        get_stat("Failures", failures)
    );
    overall_report
}

/// Returns: Either `Some(updates)` where `updates` is the number of updates made to the report or an Error.
fn update_report(
    report: &mut ClassHashesReport,
    obj: &Value,
    block_num: u64,
) -> Result<usize, anyhow::Error> {
    if report.blocks.contains(&block_num) {
        return Err(
            anyhow!("Report already contains block").context(format!("block_num: {block_num}"))
        );
    }

    let mut updates = 0;
    let transactions = obj["post_response"]
        .as_array()
        .ok_or(anyhow!("expected array"))?;
    for transaction in transactions {
        let root_call = &transaction["trace_root"]["execute_invocation"];
        if let Value::Null = root_call {
            // Most likely, this "trace_root" has no "execute_invocation".
            debug!("skipping transaction: `{transaction}`");
            continue;
        }
        let calls = get_calls(root_call).context("Failed to get calls from root_call")?;
        for call in calls {
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
fn get_calls<'a>(obj: &'a Value) -> Result<Box<dyn Iterator<Item = &Value> + 'a>, anyhow::Error> {
    // TODO (#72) Put debug logging here under a core::option_env flag so it is normally hidden.
    match obj {
        Value::String(string) => {
            if string_is_same(string) {
                Ok(Box::new(::std::iter::empty()))
            } else {
                Err(anyhow!("unexpected string: {}", string))
            }
        }
        Value::Array(call_list) => {
            let nested_calls = call_list
                .iter()
                .map(|inner_call| get_calls(inner_call))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten();
            Ok(Box::new(call_list.iter().chain(nested_calls)))
        }
        Value::Object(obj_map) => {
            if let Some(Value::Object(diff_map)) = obj_map.get(DIFFERENT) {
                let base_list = diff_map
                    .get("base")
                    .ok_or(anyhow!("difference should have base"))?;
                let native_list = diff_map
                    .get("native")
                    .ok_or(anyhow!("difference should have native"))?;
                // TODO (#72) Compare and get diffs. For now we just chain.
                Ok(Box::new(
                    get_calls(base_list)?.chain(get_calls(native_list)?),
                ))
            } else if let Some(calls_value) = obj_map.get("calls") {
                get_calls(calls_value)
            } else if let Some(_val) = obj_map.get("revert_reason") {
                Ok(Box::new(::std::iter::empty()))
            } else {
                Err(anyhow!("unexpected object: `{}`", obj))
            }
        }
        _ => Err(anyhow!("unexpected value: `{}`", obj)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_class_hashes_report_update_count() {
        let mut report = ClassHashesReport::new();
        let class_hash = FieldElement::from_hex_be("0x123").unwrap();
        let entry_point = FieldElement::from_hex_be("0x456").unwrap();

        report.update_count(class_hash, entry_point, 5);
        assert_eq!(report.report[&class_hash][&entry_point], 5);
        assert_eq!(report.totals[&class_hash], 5);

        report.update_count(class_hash, entry_point, 3);
        assert_eq!(report.report[&class_hash][&entry_point], 8);
        assert_eq!(report.totals[&class_hash], 8);
    }

    #[test]
    fn test_class_hashes_report_add_fields() {
        let mut report = ClassHashesReport::new();
        let class_hash = FieldElement::from_hex_be("0x789").unwrap();
        let entry_point = FieldElement::from_hex_be("0xabc").unwrap();

        report.add_fields(class_hash, entry_point);
        assert_eq!(report.report[&class_hash][&entry_point], 1);
        assert_eq!(report.totals[&class_hash], 1);

        report.add_fields(class_hash, entry_point);
        assert_eq!(report.report[&class_hash][&entry_point], 2);
        assert_eq!(report.totals[&class_hash], 2);
    }

    #[test]
    fn test_get_tuple_from_call() {
        let call = json!({
            "entry_point_selector": "0x123",
            "class_hash": "0x456"
        });

        let result = get_tuple_from_call(&call).unwrap();
        assert_eq!(result.0, FieldElement::from_hex_be("0x123").unwrap());
        assert_eq!(result.1, FieldElement::from_hex_be("0x456").unwrap());
    }

    #[test]
    fn test_get_calls() {
        let obj = json!({
            "calls": ["Same", "Same"]
        });

        let calls: Vec<&Value> = get_calls(&obj).collect();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_get_calls_different() {
        let obj = json!({
            "calls": [{
                "Different": {
                    "base": "dsa",
                    "native": "asd"
                }
            }]
        });
        let calls: Vec<&Value> = get_calls(&obj).collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["Different"]["base"], "dsa");
        assert_eq!(calls[0]["Different"]["native"], "asd");
    }

    #[test]
    fn test_get_calls_revert_reason() {
        let obj = json!({
            "revert_reason": "Same(0x08c379a000000000000000000000000000000000000000000000000000000000)",
        });

        let calls: Vec<&Value> = get_calls(&obj).collect();
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn test_get_calls_nested() {
        let obj = json!({
            "call_type": "Same(DELEGATE)",
            "calldata": "Same([15])",
            "caller_address": "Same(0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b)",
            "calls": [
            {
                "call_type": "Same(DELEGATE)",
                "calldata": "Same([14])",
                "caller_address": "Same(0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b)",
                "calls": [
                "Same({12})",
                {
                    "call_type": "Same(CALL)",
                    "calldata": "Same([11])",
                    "caller_address": "Same(0x4270219d365d6b017231b52e92b3fb5d7c8378b05e9abc97724537a80e93b0f)",
                    "calls": "Same([0])",
                    "class_hash": "Same(0x3e8d67c8817de7a2185d418e88d321c89772a9722b752c6fe097192114621be)",
                    "contract_address": "Same(0x5dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b)",
                    "entry_point_selector": "Same(0x15543c3708653cda9d418b4ccd3be11368e40636c10c44b18cfe756b6d88b29)",
                    "entry_point_type": "Same(EXTERNAL)",
                    "execution_resources": "Same({5})",
                    "messages": "Same([0])",
                    "result": "Same([4])"
                },
                "Same({12})",
                "Same({12})",
                "Same({12})"
                ],
            }
        ]});

        let calls: Vec<&Value> = get_calls(&obj).collect();
        assert_eq!(calls.len(), 6);
    }

    #[test]
    fn test_get_calls_nested_different() {
        let obj = json!({
                "calls": {
                    "Different": {
                        "base": [
                        {
                            "calls": [
                            {
                                "calls": [],
                            },
                            {
                              "calls": [
                                {
                                  "calls": [
                                    {
                                      "calls": [],
                                    }
                                  ],
                                }
                              ],
                            },
                            {
                              "calls": [],
                            },
                            {
                              "calls": [],
                            },
                            {
                              "calls": [],
                            },
                            {
                              "calls": [],
                            }
                          ],
                        }
                      ],
                      "native": "Empty"
                    }
                }
        });
        let calls: Vec<&Value> = get_calls(&obj).collect();
        assert_eq!(calls.len(), 9);
    }
}