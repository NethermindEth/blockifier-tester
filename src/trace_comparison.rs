use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use starknet::core::types::{StateDiff, TransactionTrace, TransactionTraceWithHash};

use crate::{block_tracer::TraceBlockReport, dependencies::block_report_with_dependencies};

const SAME: &str = "Same";
const EMPTY: &str = "Empty";
const DIFFERENT: &str = "Different";

#[derive(Serialize, Deserialize)]
pub enum ComparisonResult {
    Same,
    Different {
        base: Option<Value>,
        native: Option<Value>,
    },
}

impl ComparisonResult {
    pub fn new_same() -> Self {
        ComparisonResult::Same
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
            ComparisonResult::Same => json!(SAME),
            ComparisonResult::Different { base, native } => json!({
                DIFFERENT:{
                    "base": base.unwrap_or(Value::String(EMPTY.into())),
                    "native": native.unwrap_or(Value::String(EMPTY.into())),
                }
            }),
        }
    }
}

impl From<ComparisonResult> for Value {
    fn from(result: ComparisonResult) -> Self {
        result.into_json()
    }
}

fn trace_block_report_to_json(report: TraceBlockReport) -> Value {
    let mut traces = report.post_response.unwrap_or_default();

    normalize_traces_state_diff(&mut traces);

    json!({
        "block_num": report.block_num,
        "post_response": block_report_with_dependencies(&traces)
    })
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

// Take two JSONs and compare each (key, value) recursively.
// It will consume the two JSON as well.
// Store the resutls in an output JSON.
pub fn generate_block_comparison(
    base_report: TraceBlockReport,
    native_report: TraceBlockReport,
) -> Value {
    compare_jsons(
        trace_block_report_to_json(base_report),
        trace_block_report_to_json(native_report),
    )
}

pub fn compare_jsons(json_1: Value, json_2: Value) -> Value {
    let output = compare_json_values(json_1, json_2);
    clean_json_value(output)
}

fn compare_json_values(val_1: Value, val_2: Value) -> Value {
    match (val_1, val_2) {
        (Value::Object(obj_1), Value::Object(obj_2)) => compare_json_objects(obj_1, obj_2),
        (Value::Array(arr_1), Value::Array(arr_2)) => compare_json_arrays(arr_1, arr_2),
        (val_1, val_2) if val_1 == val_2 => ComparisonResult::new_same().into(),
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
                    "storage_diffs" => compare_storage_diffs(val_1, val_2),
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
        return ComparisonResult::new_same().into();
    }

    let output: Vec<Value> = arr_1
        .into_iter()
        .zip(arr_2)
        .map(|e| compare_json_values(e.0, e.1))
        .collect();

    Value::Array(output)
}

fn compare_storage_diffs(base_diffs: Value, native_diffs: Value) -> Value {
    // helper method to consume the value (as_array gives a reference)
    let to_array = |v: Value| match v {
        Value::Array(a) => Ok(a),
        _ => Err("Value is not an array"),
    };
    let add_value_to_map = |mut map: HashMap<String, String>, value: Value| {
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

    let base_diffs: HashMap<String, String> = to_array(base_diffs)
        .expect("Base `storage_diffs` is not an array")
        .into_iter()
        .fold(HashMap::new(), add_value_to_map);
    let mut native_diffs: HashMap<String, String> = to_array(native_diffs)
        .expect("Native `storage_diffs` is not an array")
        .into_iter()
        .fold(HashMap::new(), add_value_to_map);

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

    let all_same = cleaned_obj
        .values()
        .all(|el| matches!(el, Value::String(str) if str == SAME));

    if all_same {
        ComparisonResult::Same.into()
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
        ComparisonResult::Same.into()
    } else {
        Value::Array(cleaned_arr)
    }
}

fn value_is_same(val: &Value) -> bool {
    matches!(val, Value::String(str) if str == SAME)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(result, Value::String(SAME.into()));
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
                "Same",
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
        let base = json!(
          {
            "key_1": "a",
            "storage_dependencies": []
          }
        );

        let native = json!(
          {
            "key_1": "b",
            "storage_dependencies": []
          }
        );

        let result = compare_jsons(base, native);

        assert_eq!(
            result,
            json!(
              {
                "key_1": {
                  DIFFERENT: {
                    "base" : "a",
                    "native" : "b",
                  }
                },
                "storage_dependencies": SAME
              }
            )
        );
    }
}
