use core::panic;
use std::collections::BTreeMap;

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

    // ToDo: Not taking into account arrays with different length
    // ToDo: Not taking into account different order in the transactions
    let post_response: Vec<Value> = match (base_block_report, native_block_report) {
        (Value::Array(base), Value::Array(native)) => base
            .into_iter()
            .zip(native)
            .map(|(base_tx_trace, native_tx_trace)| {
                generate_transaction_comparions(base_tx_trace, native_tx_trace)
            })
            .collect(),
        // ToDo: Should we handle this panic accordingly
        _ => panic!("Expecting arrays "),
    };

    json!({
        "block_num": block_number,
        "post_response": post_response,
    })
}

/// Compares the trace root of two transactions
/// If the trace roots are different, it compares the contract dependencies and storage dependencies.
/// Otherwise, it skips comparison for contract dependencies and storage dependencies.
fn generate_transaction_comparions(base_tx_trace: Value, native_tx_trace: Value) -> Value {
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

    let (mut base_trace, mut native_trace) = match (base_tx_trace, native_tx_trace) {
        (Value::Object(base), Value::Object(native)) => (base, native),
        _ => panic!("base trace and native trace are expected to be objects"),
    };

    let trace_comparison = compare_traces_key(&mut base_trace, &mut native_trace, "trace_root");

    let tx_hash = {
        let hash = base_trace.get("transaction_hash").unwrap().to_owned();
        let tx_hash_comparison =
            compare_traces_key(&mut base_trace, &mut native_trace, "transaction_hash");
        if value_is_same(&tx_hash_comparison) {
            hash
        } else {
            tx_hash_comparison
        }
    };

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
        let result = generate_transaction_comparions(base_trace, native_trace);
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

        let result = generate_transaction_comparions(base_trace, native_trace);
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
