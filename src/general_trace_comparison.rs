use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::block_tracer::TraceBlockReport;

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
                "comparison": DIFFERENT,
                "base": base.unwrap_or(Value::String(EMPTY.into())),
                "native": native.unwrap_or(Value::String(EMPTY.into())),
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
    json!({
        "block_num": report.block_num,
        "post_response": serde_json::value::to_value(report.post_response.unwrap_or_default()).unwrap(),
    })
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
        (val_1, val_2) if val_1 == val_2 => ComparisonResult::Same.into(),
        (val_1, val_2) => ComparisonResult::new_different(val_1, val_2).into(),
    }
}

fn compare_json_objects(obj_1: Map<String, Value>, mut obj_2: Map<String, Value>) -> Value {
    // Object to store the comparison results per key
    let mut output = Map::<String, Value>::new();

    for (key_1, val_1) in obj_1 {
        match obj_2.remove(&key_1) {
            Some(val_2) => output.insert(key_1, compare_json_values(val_1, val_2)),
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

    let output: Vec<Value> = arr_1
        .into_iter()
        .zip(arr_2)
        .map(|e| compare_json_values(e.0, e.1))
        .collect();

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
                    "comparison": DIFFERENT,
                    "base": "value1",
                    "native": "value1-2",
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
                    "comparison": DIFFERENT,
                    "base": "value1",
                    "native": EMPTY,
                },
                "key2": {
                    "comparison": DIFFERENT,
                    "base": EMPTY,
                    "native": "value2",
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
                    "comparison": DIFFERENT,
                    "base": "value2",
                    "native": "value2-2",
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
                    "comparison": DIFFERENT,
                    "base": ["value1", "value2"],
                    "native": ["value1", "value2", "value3"],
                }
            )
        );
    }
}
