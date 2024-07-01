use std::iter::zip;

use serde_json::{json, Map, Value};

use crate::block_tracer::TraceBlockReport;

// Take two JSONs and compare each (key, value) recursively.
// It will consume the two JSON as well.
// Store the resutls in an output JSON.

pub fn generate_block_comparison(base_report: TraceBlockReport, native_report: TraceBlockReport) {}

pub fn compare_jsons(json1: Value, json2: Value) -> Value {
    let output = compare_json_values(json1, json2);
    clean_json_value(output)
}

fn compare_json_values(val1: Value, val2: Value) -> Value {
    match (val1, val2) {
        (Value::Object(obj1), Value::Object(obj2)) => compare_json_objects(obj1, obj2),
        (Value::Array(arr1), Value::Array(arr2)) => compare_json_arrays(arr1, arr2),
        (val1, val2) => {
            if val1 == val2 {
                build_same_result()
            } else {
                build_different_result(Some(val1), Some(val2))
            }
        }
    }
}

fn compare_json_objects(obj1: Map<String, Value>, mut obj2: Map<String, Value>) -> Value {
    // Object to store the comparison results per key
    let mut output_obj = Map::<String, Value>::new();

    for (key1, val1) in obj1 {
        match obj2.remove(&key1) {
            Some(val2) => output_obj.insert(key1, compare_json_values(val1, val2)),
            None => todo!("Compare an existing object with a non different one"),
        };
    }

    for (key2, val2) in obj2 {
        output_obj.insert(key2, build_different_result(None, Some(val2)));
    }

    Value::Object(output_obj)
}

fn compare_json_arrays(arr1: Vec<Value>, arr2: Vec<Value>) -> Value {
    if arr1.len() != arr2.len() {
        return build_different_result(Some(Value::Array(arr1)), Some(Value::Array(arr2)));
    }

    let mut output = Vec::<Value>::new();
    for (v1, v2) in zip(arr1, arr2) {
        output.push(compare_json_values(v1, v2));
    }

    Value::Array(output)
}

// Creates a string "Same" signaling two JSON Values are the same
fn build_same_result() -> Value {
    return Value::String("Same".into());
}

// Creates an object signaling two values are different
fn build_different_result(left: Option<Value>, right: Option<Value>) -> Value {
    let left = left.unwrap_or(Value::String("Empty".into()));
    let right = right.unwrap_or(Value::String("Empty".into()));
    return json!({
        "comparison": "Different",
        "base": left,
        "native": right,
    });
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
        .all(|el| matches!(el, Value::String(str) if str == "Same"));

    if all_same {
        build_same_result()
    } else {
        Value::Object(cleaned_obj)
    }
}

fn clean_json_array(arr: Vec<Value>) -> Value {
    let cleaned_arr: Vec<Value> = arr.into_iter().map(|val| clean_json_value(val)).collect();
    let all_same = cleaned_arr.iter().all(value_is_same);

    if all_same {
        build_same_result()
    } else {
        Value::Array(cleaned_arr)
    }
}

fn value_is_same(val: &Value) -> bool {
    matches!(val, Value::String(str) if str == "Same")
}
