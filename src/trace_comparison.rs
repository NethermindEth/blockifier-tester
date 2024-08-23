use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use starknet::core::types::{StateDiff, TransactionTrace, TransactionTraceWithHash};

use crate::dependencies::block_report_with_dependencies;

pub const SAME: &str = "Same";
pub const EMPTY: &str = "Empty";
pub const DIFFERENT: &str = "Different";

#[derive(Serialize, Deserialize)]
pub enum ComparisonResult {
    Same(Value),
    Different {
        base: Option<Value>,
        native: Option<Value>,
    },
}

impl ComparisonResult {
    pub fn new_same(val: Value) -> Self {
        ComparisonResult::Same(val)
    }

    pub fn new_different(base: Value, native: Value) -> Self {
        ComparisonResult::Different {
            base: Some(base),
            native: Some(native),
        }
    }

    pub fn new_different_base_only(base: Value) -> Self {
        ComparisonResult::Different {
            base: Some(base),
            native: None,
        }
    }

    pub fn new_different_native_only(native: Value) -> Self {
        ComparisonResult::Different {
            base: None,
            native: Some(native),
        }
    }

    pub fn into_json(self) -> Value {
        match self {
            ComparisonResult::Same(val) => {
                let repr = format!("({})", ComparisonResult::value_to_short_representation(val));
                json!(format!("{SAME}{repr}"))
            }
            ComparisonResult::Different { base, native } => json!({
                DIFFERENT:{
                    "base": base.unwrap_or(Value::String(EMPTY.into())),
                    "native": native.unwrap_or(Value::String(EMPTY.into())),
                }
            }),
        }
    }

    // utility
    pub fn value_to_short_representation(val: Value) -> String {
        match val {
            Value::Array(a) => format!("[{}]", a.len()),
            Value::Object(b) => format!("{{{}}}", b.len()),
            Value::Null => String::from("null"),
            Value::String(s) => s,
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
        }
    }
}

impl From<ComparisonResult> for Value {
    fn from(result: ComparisonResult) -> Self {
        result.into_json()
    }
}

fn normalize_traces_state_diff(traces: &mut Vec<TransactionTraceWithHash>) {
    let normalize = |maybe_state_diff: &mut Option<StateDiff>| {
        if let Some(state_diff) = maybe_state_diff {
            state_diff
                .storage_diffs
                .sort_by(|lhs, rhs| lhs.address.cmp(&rhs.address))
        }
    };

    for trace in traces {
        match &mut trace.trace_root {
            TransactionTrace::Invoke(tx) => normalize(&mut tx.state_diff),
            TransactionTrace::Declare(tx) => normalize(&mut tx.state_diff),
            TransactionTrace::DeployAccount(tx) => normalize(&mut tx.state_diff),
            TransactionTrace::L1Handler(tx) => normalize(&mut tx.state_diff),
        }
    }
}

pub fn generate_block_comparison(
    block_number: u64,
    mut base_traces: Vec<TransactionTraceWithHash>,
    mut native_traces: Vec<TransactionTraceWithHash>,
) -> Value {
    normalize_traces_state_diff(&mut base_traces);
    normalize_traces_state_diff(&mut native_traces);

    let base_block_report = block_report_with_dependencies(&base_traces);
    let native_block_report = block_report_with_dependencies(&native_traces);

    let post_response = match (base_block_report.as_array(), native_block_report.as_array()) {
        (Some(base), Some(native)) => compare_traces(base, native),
        // TODO: Should we handle this panic accordingly
        _ => panic!("base block report and native block report are expected to be arrays"),
    };

    json!({
        "block_num": block_number,
        "post_response": post_response,
    })
}

/// Compares two lists of transaction traces (base and native):
/// 1. Iterates through both lists simultaneously, comparing transactions by hash:
///    - If hashes match, compares transactions directly.
///    - If mismatch, searches for matching transaction in the other list.
/// 2. Handles unmatched transactions by comparing with "Empty" and adjusting indices,
///    with a preference for base transactions.
fn compare_traces(base_traces: &[Value], native_traces: &[Value]) -> Value {
    fn create_hash_map(traces: &[Value]) -> HashMap<String, usize> {
        traces
            .iter()
            .enumerate()
            .map(|(idx, trace)| {
                (
                    trace["transaction_hash"]
                        .as_str()
                        .expect("Transaction hash is not a string")
                        .to_string(),
                    idx,
                )
            })
            .collect()
    }

    let mut compare_traces_result = Vec::new();
    let mut base_idx = 0;
    let mut native_idx = 0;

    // To look up indices of transaction hashes, in the event that the ordering of transactions is different
    let base_hash_map = create_hash_map(base_traces);
    let native_hash_map = create_hash_map(native_traces);

    while base_idx < base_traces.len() || native_idx < native_traces.len() {
        if base_idx >= base_traces.len() {
            // Only native transactions left
            compare_traces_result.push(
                ComparisonResult::new_different_native_only(native_traces[native_idx].clone())
                    .into(),
            );
            native_idx += 1;
        } else if native_idx >= native_traces.len() {
            // Only base transactions left
            compare_traces_result.push(
                ComparisonResult::new_different_base_only(base_traces[base_idx].clone()).into(),
            );
            base_idx += 1;
        } else {
            // There are both base and native transactions left
            let base_trace = &base_traces[base_idx];
            let native_trace = &native_traces[native_idx];

            let (base_tx_hash, native_tx_hash) = match (
                base_trace["transaction_hash"].as_str(),
                native_trace["transaction_hash"].as_str(),
            ) {
                (Some(base), Some(native)) => (base, native),
                _ => panic!("Base trace and native trace are expected to be strings"),
            };

            if base_tx_hash == native_tx_hash {
                let (base_trace, native_trace) =
                    match (base_trace.as_object(), native_trace.as_object()) {
                        (Some(base), Some(native)) => (base, native),
                        _ => panic!("Base trace and native trace are expected to be objects"),
                    };
                compare_traces_result.push(generate_transaction_comparisons(
                    base_trace.clone(),
                    native_trace.clone(),
                    base_tx_hash,
                ));
                base_idx += 1;
                native_idx += 1;
            } else if let Some(&native_match_idx) = native_hash_map.get(base_tx_hash) {
                // Found a match for base transaction in native
                for i in native_idx..native_match_idx {
                    compare_traces_result.push(
                        ComparisonResult::new_different_native_only(native_traces[i].clone())
                            .into(),
                    );
                }
                native_idx = native_match_idx;
            } else if let Some(&base_match_idx) = base_hash_map.get(native_tx_hash) {
                // Found a match for native transaction in base
                for i in base_idx..base_match_idx {
                    compare_traces_result.push(
                        ComparisonResult::new_different_base_only(base_traces[i].clone()).into(),
                    );
                }
                base_idx = base_match_idx;
            } else {
                // No match found, we keep adding base transactions first
                compare_traces_result
                    .push(ComparisonResult::new_different_base_only(base_trace.clone()).into());
                base_idx += 1;
            }
        }
    }

    Value::Array(compare_traces_result)
}

/// Compares the trace root of two transactions
/// If the trace roots are different, it compares the contract dependencies and storage dependencies.
/// Otherwise, it skips comparison for contract dependencies and storage dependencies.
fn generate_transaction_comparisons(
    mut base_trace: Map<String, Value>,
    mut native_trace: Map<String, Value>,
    tx_hash: &str,
) -> Value {
    // Helper function to compare individual keys
    fn compare_traces_key(
        base_trace: &mut Map<String, Value>,
        native_trace: &mut Map<String, Value>,
        key: &str,
    ) -> Value {
        let base = base_trace.remove(key).unwrap();
        let native = native_trace.remove(key).unwrap();
        compare_jsons(base, native)
    }

    let trace_comparison = compare_traces_key(&mut base_trace, &mut native_trace, "trace_root");

    if value_is_same(&trace_comparison) {
        json!({
            "transaction_hash": tx_hash,
            "trace_root": trace_comparison,
        })
    } else {
        let contract_dependencies =
            compare_traces_key(&mut base_trace, &mut native_trace, "contract_dependencies");
        let storage_dependencies =
            compare_traces_key(&mut base_trace, &mut native_trace, "storage_dependencies");

        json!({
            "transaction_hash": tx_hash,
            "trace_root": trace_comparison,
            "contract_dependencies": contract_dependencies,
            "storage_dependencies": storage_dependencies,
        })
    }
}

/// Take two JSONs and compare each (key, value) recursively.
/// Store the results in an output JSON.
pub fn compare_jsons(json_1: Value, json_2: Value) -> Value {
    let output = compare_json_values(json_1, json_2);
    clean_json_value(output)
}

fn compare_json_values(val_1: Value, val_2: Value) -> Value {
    match (val_1.clone(), val_2.clone()) {
        (Value::Object(obj_1), Value::Object(obj_2)) => compare_json_objects(obj_1, obj_2),
        (Value::Array(arr_1), Value::Array(arr_2)) => compare_json_arrays(arr_1, arr_2),
        (val_1, val_2) if val_1 == val_2 => ComparisonResult::new_same(val_1).into(),
        (val_1, val_2) => ComparisonResult::new_different(val_1, val_2).into(),
    }
}

fn compare_json_objects(obj_1: Map<String, Value>, mut obj_2: Map<String, Value>) -> Value {
    // Object to store the comparison results per key
    let mut output = Map::<String, Value>::new();

    // TODO: we might to have special handles for special keys. For example:
    // 1. For error messages ('revert-reason'), which are fundamentally different but might say the
    // same thing, we can implement Levenshtein Distance or TF-IDF. Or we can modifiy the error
    // messages in Native to look similar to the ones in Base.

    for (key_1, val_1) in obj_1 {
        match obj_2.remove(&key_1) {
            Some(val_2) => {
                let compare_result = match key_1.as_str() {
                    "storage_entries" => compare_storage_entries(val_1, val_2),
                    // We are blatantly ignoring execution resources since they won't be the same
                    // for the near future.
                    "execution_resources" => ComparisonResult::new_same(val_1).into(),
                    _ => compare_json_values(val_1, val_2),
                };
                output.insert(key_1, compare_result)
            }
            None => output.insert(
                key_1,
                ComparisonResult::new_different_base_only(val_1).into(),
            ),
        };
    }

    for (key_2, val_2) in obj_2 {
        output.insert(
            key_2,
            ComparisonResult::new_different_native_only(val_2).into(),
        );
    }

    Value::Object(output)
}

fn compare_json_arrays(arr_1: Vec<Value>, arr_2: Vec<Value>) -> Value {
    if arr_1.len() != arr_2.len() {
        return ComparisonResult::new_different(Value::Array(arr_1), Value::Array(arr_2)).into();
    }

    if arr_1.is_empty() && arr_2.is_empty() {
        return ComparisonResult::new_same(Value::Array(arr_1)).into();
    }

    let output: Vec<Value> = arr_1
        .into_iter()
        .zip(arr_2)
        .map(|e| compare_json_values(e.0, e.1))
        .collect();

    Value::Array(output)
}

fn compare_storage_entries(base_diffs: Value, native_diffs: Value) -> Value {
    let add_value_to_map = |mut map: BTreeMap<String, String>, value: Value| {
        let obj = value.as_object().expect("Value is not an object");

        let key = obj
            .get("key")
            .expect("No `key` field")
            .as_str()
            .expect("`key` field is not a string")
            .to_owned();
        let value = obj
            .get("value")
            .expect("No `value` field")
            .as_str()
            .expect("`value` field is not a string")
            .to_owned();

        map.insert(key, value);
        map
    };

    // helper method to consume the value (as_array gives a reference)
    let to_array = |v: Value| match v {
        Value::Array(a) => Ok(a),
        _ => Err("Value is not an array"),
    };
    // Using BTrees instead of HashMaps so that comparison results
    // stay with the same order across runs
    let base_diffs: BTreeMap<String, String> = to_array(base_diffs)
        .expect("Base `storage_diffs` is not an array")
        .into_iter()
        .fold(BTreeMap::new(), add_value_to_map);
    let mut native_diffs: BTreeMap<String, String> = to_array(native_diffs)
        .expect("Native `storage_diffs` is not an array")
        .into_iter()
        .fold(BTreeMap::new(), add_value_to_map);

    let mut output: Vec<Value> = vec![];
    let kv_to_json = |k, v| json!({"key": k, "value": v});
    for (base_key, base_val) in base_diffs {
        let comp = if let Some(native_val) = native_diffs.remove(&base_key) {
            compare_json_values(
                kv_to_json(base_key.clone(), base_val),
                kv_to_json(base_key, native_val),
            )
        } else {
            ComparisonResult::new_different_base_only(kv_to_json(base_key, base_val)).into()
        };
        output.push(comp);
    }
    for (native_key, native_val) in native_diffs {
        let comp =
            ComparisonResult::new_different_native_only(kv_to_json(native_key, native_val)).into();
        output.push(comp);
    }

    Value::Array(output)
}

fn clean_json_value(val: Value) -> Value {
    match val {
        Value::Object(obj) => clean_json_object(obj),
        Value::Array(arr) => clean_json_array(arr),
        val => val,
    }
}

fn clean_json_object(obj: Map<String, Value>) -> Value {
    let mut cleaned_obj = Map::<String, Value>::new();
    for (key, val) in obj {
        cleaned_obj.insert(key, clean_json_value(val));
    }

    let all_same = cleaned_obj.values().all(value_is_same);
    if all_same {
        ComparisonResult::new_same(Value::Object(cleaned_obj)).into()
    } else {
        Value::Object(cleaned_obj)
    }
}

fn clean_json_array(arr: Vec<Value>) -> Value {
    if arr.is_empty() {
        // Don't count empty arrays as all same.
        // An empty array is a different value.
        return Value::Array(arr);
    }

    let cleaned_arr: Vec<Value> = arr.into_iter().map(clean_json_value).collect();

    let all_same = cleaned_arr.iter().all(value_is_same);
    if all_same {
        ComparisonResult::new_same(Value::Array(cleaned_arr)).into()
    } else {
        Value::Array(cleaned_arr)
    }
}

fn value_is_same(val: &Value) -> bool {
    matches!(val, Value::String(str) if str.starts_with(SAME))
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use super::*;
    use itertools::enumerate;

    #[test]
    fn test_all_same() {
        let base = json!({
            "key1": "value1",
            "key2": "value2",
            "key3": {
                "key4": "value4",
                "key5": "value5",
            },
            "key6": [
                "value6",
                "value7",
                "value8",
            ],
        });

        let native = json!({
            "key1": "value1",
            "key2": "value2",
            "key3": {
                "key4": "value4",
                "key5": "value5",
            },
            "key6": [
                "value6",
                "value7",
                "value8",
            ],
        });

        let result = compare_jsons(base, native);

        assert_eq!(result, same_object_repr(4));
    }

    #[test]
    fn test_some_different_1() {
        let base = json!({
            "key1": "value1",
        });

        let native = json!({
            "key1": "value1-2",
        });

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!({
                "key1": {
                    DIFFERENT: {
                        "base": "value1",
                        "native": "value1-2",
                    }
                }
            })
        );
    }

    #[test]
    fn test_different_keys() {
        let base = json!({
            "key1": "value1",
        });

        let native = json!({
            "key2": "value2",
        });

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!({
                "key1": {
                    DIFFERENT: {
                        "base": "value1",
                        "native": EMPTY
                    }
                },
                "key2": {
                     DIFFERENT: {
                        "base": EMPTY,
                        "native": "value2"
                     }
                }
            })
        );
    }

    #[test]
    fn test_different_array() {
        let base = json!(["value1", "value2",]);

        let native = json!(["value1", "value2-2",]);

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!([
                same_value_repr("value1"),
                {
                    DIFFERENT: {
                        "base": "value2",
                        "native": "value2-2",
                    }
                }
            ])
        );
    }

    #[test]
    fn test_different_array_length() {
        let base = json!(["value1", "value2",]);

        let native = json!(["value1", "value2", "value3",]);

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!(
                {
                     DIFFERENT: {
                        "base": ["value1", "value2"],
                        "native": ["value1", "value2", "value3"],
                     }
                }
            )
        );
    }

    #[test]
    fn test_different_empty_list() {
        let native = json!(
          {
            "post_response": [
              {
                "contract_dependencies": [
                  "0x11d75966a7514052309ce01f62e6d48f2be6158254d22d306e71a3ad07d5c62"
                ],
                "storage_dependencies": [
                  "0x11d75966a7514052309ce01f62e6d48f2be6158254d22d306e71a3ad07d5c62"
                ]
              }
            ]
          }
        );

        let base = json!(
          {
            "post_response": [
              {
                "contract_dependencies": [],
                "storage_dependencies": []
              }
            ]
          }
        );

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!(
              {
                "post_response": [
                  {
                    "contract_dependencies": {
                      DIFFERENT: {
                        "base": [],
                        "native": [
                            "0x11d75966a7514052309ce01f62e6d48f2be6158254d22d306e71a3ad07d5c62"
                        ]
                      }
                    },
                    "storage_dependencies": {
                      DIFFERENT: {
                        "base": [],
                        "native": [
                          "0x11d75966a7514052309ce01f62e6d48f2be6158254d22d306e71a3ad07d5c62"
                        ]
                      }
                    }
                  }
                ]
              }
            )
        );
    }

    #[test]
    fn test_both_empty_list() {
        let base = json!([]);
        let native = json!([]);

        let result = compare_jsons(base, native);

        assert_eq!(result, json!(same_array_repr(0)));
    }

    #[test]
    fn test_compare_storage_diffs() {
        struct Params {
            input: (Value, Value),
            output: Value,
        }
        let kv_to_json = |k, v| json!({"key": k, "value": v});

        let test_params = vec![
            // 0
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                    json!([kv_to_json("k1", "v1"), kv_to_json("k0", "v0"),]),
                ),
                output: json!(same_array_repr(2)),
            },
            // 1
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1")]),
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("k1", "v1"),
                        kv_to_json("kw", "vw"),
                    ]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_native_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 2
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1")]),
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("k1", "v1"),
                        kv_to_json("kw", "vw"),
                    ]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_native_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 3
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1")]),
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("kw", "vw"),
                        kv_to_json("k1", "v1"),
                    ]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_native_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 4
            Params {
                input: (
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("k1", "v1"),
                        kv_to_json("kw", "vw")
                    ]),
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_base_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 5
            Params {
                input: (
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("k1", "v1"),
                        kv_to_json("kw", "vw"),
                    ]),
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_base_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 6
            Params {
                input: (
                    json!([
                        kv_to_json("k0", "v0"),
                        kv_to_json("kw", "vw"),
                        kv_to_json("k1", "v1"),
                    ]),
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_base_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
            // 7
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("kw", "vw"),]),
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_base_only(kv_to_json("kw", "vw")).into_json(),
                    ComparisonResult::new_different_native_only(kv_to_json("k1", "v1")).into_json(),
                ]),
            },
            // 8
            Params {
                input: (
                    json!([kv_to_json("k0", "v0"), kv_to_json("k1", "v1"),]),
                    json!([kv_to_json("k0", "v0"), kv_to_json("kw", "vw"),]),
                ),
                output: json!([
                    json!(same_object_repr(2)),
                    ComparisonResult::new_different_base_only(kv_to_json("k1", "v1")).into_json(),
                    ComparisonResult::new_different_native_only(kv_to_json("kw", "vw")).into_json(),
                ]),
            },
        ];

        for (i, param) in enumerate(test_params) {
            let expected = param.output;
            let result = clean_json_value(compare_storage_entries(param.input.0, param.input.1));

            assert_eq!(
                expected,
                result,
                "Test {i}\nExpected:\n{}\nResult:\n{}",
                serde_json::to_string_pretty(&expected).unwrap(),
                serde_json::to_string_pretty(&result).unwrap()
            )
        }
    }

    #[test]
    fn test_generate_block_comparison() {
        let base_trace = json!({
            "contract_dependencies": "[0]",
            "storage_dependencies": "[0]",
            "trace_root": {
                "execute_invocation": {
                    "call_type": "CALL",
                    "calldata": "[8]",
                    "caller_address": "0x0",
                    "calls": [{
                        "call_type": "CALL",
                        "calldata": "[4]",
                        "caller_address": "0x9f481dc204eef7d51f908fb6243be9a0d96d872053233dccdf131109b6e398",
                        "calls": []
                    }]
                },
            },
            "transaction_hash": "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9"
        });
        let native_trace = base_trace.clone();
        let base = base_trace.as_object().unwrap();
        let native = native_trace.as_object().unwrap();
        let result = generate_transaction_comparisons(
            base.clone(),
            native.clone(),
            "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9",
        );
        assert_eq!(
            result,
            json!({
                "trace_root": "Same({1})",
                "transaction_hash": "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9"
            })
        );

        let base_trace = json!({
            "contract_dependencies": "[0]",
            "storage_dependencies": "[0]",
            "trace_root": {
                "execute_invocation": {
                    "call_type": "CALL",
                    "calldata": "[8]",
                    "caller_address": "0x1",
                    "calls": [{
                        "call_type": "CALL",
                        "calldata": "[4]",
                        "caller_address": "0x9f481dc204eef7d51f908fb6243be9a0d96d872053233dccdf131109b6e398",
                        "calls": []
                    }]
                },
            },
            "transaction_hash": "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9"
        });
        let native_trace = json!({
            "contract_dependencies": "[0]",
            "storage_dependencies": "[0]",
            "trace_root": {
                "execute_invocation": {
                    "call_type": "CALL",
                    "calldata": "[8]",
                    "caller_address": "0x0",
                    "calls": [{
                        "call_type": "CALL",
                        "calldata": "[4]",
                        "caller_address": "0x9f481dc204eef7d51f908fb6243be9a0d96d872053233dccdf131109b6e398",
                        "calls": []
                    }]
                },
            },
            "transaction_hash": "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9"
        });

        let base = base_trace.as_object().unwrap();
        let native = native_trace.as_object().unwrap();
        let result = generate_transaction_comparisons(
            base.clone(),
            native.clone(),
            "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9",
        );
        assert_eq!(
            result,
            json!({
                "contract_dependencies": "Same([0])",
                "storage_dependencies": "Same([0])",
                "trace_root": {
                    "execute_invocation": {
                        "call_type": "Same(CALL)",
                        "calldata": "Same([8])",
                        "caller_address": {
                            "Different": {
                                "base": "0x1",
                                "native": "0x0"
                            }
                        },
                        "calls": "Same([1])"
                    }
                },
                "transaction_hash": "0x2b843f740cfcc46d581299e3b3353008d8025aa9973fb8506caf6e8daa1d8c9"
            })
        );
    }

    fn create_tx(hash: &str) -> Value {
        json!({
            "contract_dependencies": "[0]",
            "storage_dependencies": "[0]",
            "trace_root": {
                "execute_invocation": {
                    "call_type": "CALL",
                    "calldata": "[8]",
                    "caller_address": "0x0",
                    "calls": [{
                        "call_type": "CALL",
                        "calldata": "[4]",
                        "caller_address": "0x9f481dc204eef7d51f908fb6243be9a0d96d872053233dccdf131109b6e398",
                        "calls": []
                    }]
                },
            },
            "transaction_hash": hash,
        })
    }

    #[test]
    fn test_identical_traces() {
        let base = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let native = base.clone();
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap();

        assert_eq!(result_arr.len(), 3);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["transaction_hash"], "tx2");
        assert_eq!(result_arr[2]["transaction_hash"], "tx3");
    }

    #[test]
    fn test_missing_transaction_in_native() {
        let base = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let native = vec![create_tx("tx1"), create_tx("tx2")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3

        assert_eq!(result_arr.len(), 3);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["transaction_hash"], "tx2");
        assert_eq!(result_arr[2]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[2]["Different"]["base"]["transaction_hash"],
            "tx3"
        );

        let base = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let native = vec![create_tx("tx1"), create_tx("tx3")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3

        assert_eq!(result_arr.len(), 3);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["base"]["transaction_hash"],
            "tx2"
        );
        assert_eq!(result_arr[2]["transaction_hash"], "tx3");
    }

    #[test]
    fn test_missing_transaction_in_base() {
        let base = vec![create_tx("tx1"), create_tx("tx2")];
        let native = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3
        assert_eq!(result_arr.len(), 3);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["transaction_hash"], "tx2");
        assert_eq!(result_arr[2]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[2]["Different"]["native"]["transaction_hash"],
            "tx3"
        );

        let base = vec![create_tx("tx1"), create_tx("tx3")];
        let native = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3

        assert_eq!(result_arr.len(), 3);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["native"]["transaction_hash"],
            "tx2"
        );
        assert_eq!(result_arr[2]["transaction_hash"], "tx3");
    }

    #[test]
    fn test_missing_transaction_in_both() {
        let base = vec![create_tx("tx1"), create_tx("tx2"), create_tx("tx3")];
        let native = vec![create_tx("tx1"), create_tx("tx4"), create_tx("tx5")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3 tx4 tx5

        assert_eq!(result_arr.len(), 5);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["base"]["transaction_hash"],
            "tx2"
        );
        assert_eq!(result_arr[2]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[2]["Different"]["base"]["transaction_hash"],
            "tx3"
        );
        assert_eq!(result_arr[3]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[3]["Different"]["native"]["transaction_hash"],
            "tx4"
        );
        assert_eq!(result_arr[4]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[4]["Different"]["native"]["transaction_hash"],
            "tx5"
        );
    }

    #[test]
    fn test_completely_different_transactions() {
        let base = vec![create_tx("tx1"), create_tx("tx2")];
        let native = vec![create_tx("tx3"), create_tx("tx4")];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1 tx2 tx3 tx4

        assert_eq!(result_arr.len(), 4);
        assert_eq!(result_arr[0]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[0]["Different"]["base"]["transaction_hash"],
            "tx1"
        );
        assert_eq!(result_arr[1]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["base"]["transaction_hash"],
            "tx2"
        );
        assert_eq!(result_arr[2]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[2]["Different"]["native"]["transaction_hash"],
            "tx3"
        );
        assert_eq!(result_arr[3]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[3]["Different"]["native"]["transaction_hash"],
            "tx4"
        );
    }

    #[test]
    fn test_mixed_scenario() {
        let base = vec![
            create_tx("tx1"),
            create_tx("tx2"),
            create_tx("tx4"),
            create_tx("tx5"),
        ];
        let native = vec![
            create_tx("tx1"),
            create_tx("tx3"),
            create_tx("tx4"),
            create_tx("tx6"),
        ];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap(); // tx1, tx2, tx3, tx4, tx5, tx6

        assert_eq!(result_arr.len(), 6);
        assert_eq!(result_arr[0]["transaction_hash"], "tx1");
        assert_eq!(result_arr[1]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["base"]["transaction_hash"],
            "tx2"
        );
        assert_eq!(result_arr[2]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[2]["Different"]["native"]["transaction_hash"],
            "tx3"
        );
        assert_eq!(result_arr[3]["transaction_hash"], "tx4");
        assert_eq!(result_arr[4]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[4]["Different"]["base"]["transaction_hash"],
            "tx5"
        );
        assert_eq!(result_arr[5]["Different"]["base"], "Empty");
        assert_eq!(
            result_arr[5]["Different"]["native"]["transaction_hash"],
            "tx6"
        );
    }

    #[test]
    fn test_empty_traces() {
        let base: Vec<Value> = vec![];
        let native: Vec<Value> = vec![];
        let result = compare_traces(&base, &native);
        assert_eq!(result, json!([]));
    }

    #[test]
    fn test_one_empty_trace() {
        let base = vec![create_tx("tx1"), create_tx("tx2")];
        let native: Vec<Value> = vec![];
        let result = compare_traces(&base, &native);
        let result_arr = result.as_array().unwrap();
        assert_eq!(result_arr.len(), 2);
        assert_eq!(result_arr[0]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[0]["Different"]["base"]["transaction_hash"],
            "tx1"
        );
        assert_eq!(result_arr[1]["Different"]["native"], "Empty");
        assert_eq!(
            result_arr[1]["Different"]["base"]["transaction_hash"],
            "tx2"
        );
    }

    fn same_array_repr(len: usize) -> String {
        format!("{SAME}([{len}])")
    }
    fn same_object_repr(len: usize) -> String {
        format!("{SAME}({{{len}}})")
    }
    fn same_value_repr<T>(val: T) -> String
    where
        T: Display,
    {
        format!("{SAME}({val})")
    }
}
