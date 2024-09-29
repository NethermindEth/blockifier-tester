// Contains functions for the trim sub command.

use crate::{
    io::{self, try_deserialize, try_serialize},
    juno_manager::Network,
    trace_comparison::value_is_same,
};

use itertools::Itertools;
use log::info;
use serde_json::{Map, Value};

use crate::trace_comparison::DIFFERENT;

pub struct TrimConfig {
    pub level: usize,
}

/// Trims a given comparison file.
/// Trimming removes extraneous Same values in the comparison json Value.
/// Values are considered extraneous if they cannot be reached by moving up from a Different value
/// in a number of steps defined in the passed `config`. Siblings of nonextraneous values are also kept.
/// For example, if passed 1, then all Same values that are not siblings of values than can be reached
/// by moving up 1 or less steps from a Different value would be omitted.
pub async fn trim_comparison_file(
    block_num: u64,
    network: Network,
    config: TrimConfig,
) -> Result<(), anyhow::Error> {
    let in_path = io::succesful_comparison_path(block_num, network);
    let in_path_name = in_path.file_name().unwrap().to_str().unwrap();
    info!("Processing path: `{}`", in_path_name);
    let comparison: Value = try_deserialize(&in_path)?;

    info!("Trimming comparison.");
    let trimmed_comparison = trim_comparison(comparison, &config);

    let out_path = io::trimmed_comparison_path(block_num, network);
    let out_path_name = out_path.file_name().unwrap().to_str().unwrap();
    info!("Processing path: `{}`", out_path_name);
    try_serialize(out_path, trimmed_comparison)?;

    Ok(())
}

fn propagate_diff_up(node: &mut rctree::Node<usize>, value: usize) {
    let new_value = value.min(*(*node).borrow());
    *node.borrow_mut() = new_value;

    // Siblings are always just as close to Different as each other.
    // This must be done after the entire tree is built.
    // If this is done during the building of the tree, some siblings may not exist.
    // Ex. Siblings: A, B, C where B has a child Different. We would update A and B, but not C.
    // Note that if more than one sibling has a Different as a descendant, the value.min logic above will
    // ensure that the min is used for all siblings.
    for sibling in node.preceding_siblings().chain(node.following_siblings()) {
        *sibling.borrow_mut() = new_value;
    }

    if let Some(parent) = node.parent().as_mut() {
        propagate_diff_up(parent, value.saturating_add(1));
    }
}

/// Build a tree mirroring the tree of `value` where each node represents the "distance" from a map
/// with Different as its key. The "distance" is not the true distance, but instead the distance
/// traveling up, where siblings are always all the same distance from a difference as each other.
fn build_diff_map_inner(
    value: &Value,
    node: &mut rctree::Node<usize>,
    diff_nodes: &mut Vec<rctree::Node<usize>>,
) {
    match value {
        Value::Array(vec) => {
            for child in vec {
                node.append(rctree::Node::<usize>::new(usize::MAX));
                let mut new_node = node.last_child().unwrap();
                build_diff_map_inner(child, &mut new_node, diff_nodes);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                node.append(rctree::Node::<usize>::new(usize::MAX));
                let mut new_node = node.last_child().unwrap().clone();
                if key == DIFFERENT {
                    let diff_node = node.last_child().unwrap().clone();
                    diff_nodes.push(diff_node);
                }
                build_diff_map_inner(val, &mut new_node, diff_nodes);
            }
        }
        _ => (),
    }
}

/// Creates a tree mirroring the Value passed in but with nodes of usize.
/// Each node value represents how far up a Value is from a Value that of type Different.
/// Note that this is not the true distance from a Different, because distance is only updated
/// by going up the tree and for siblings in Array or Map values.
/// For example, the following structure, where nodes are named by their "diff_distance":
///       2
///      / \
///     1   1
///    /     \
///   ∞       Different (0)
///  /        /   \
/// ∞       base   native
fn build_diff_map(value: &Value) -> rctree::Node<usize> {
    let mut tree = rctree::Node::<usize>::new(usize::MAX);

    // Track the Different nodes so we can propagate the distance from Different up.
    let mut diff_nodes = vec![];
    build_diff_map_inner(value, &mut tree, &mut diff_nodes);

    for mut node in diff_nodes {
        propagate_diff_up(&mut node, 0);
    }

    tree
}

/// Remove Same values from the tree based off of the diff_map and the config passed in.
fn trim_value(value: Value, diff_map: &rctree::Node<usize>, config: &TrimConfig) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let trimmed_map = Map::<_, _>::from_iter(map.into_iter().enumerate().filter_map(
                |(index, (key, child_val))| {
                    let child_diff_map = diff_map.children().nth(index).unwrap();
                    let trimmed_child = trim_value(child_val, &child_diff_map, config);
                    trimmed_child.map(|trimmed_value| (key, trimmed_value))
                },
            ));
            Some(serde_json::Value::Object(trimmed_map))
        }
        Value::Array(vec) => {
            let trimmed_vec = vec
                .into_iter()
                .enumerate()
                .filter_map(|(index, child_val)| {
                    let child_diff_map = diff_map.children().nth(index).unwrap();
                    trim_value(child_val, &child_diff_map, config)
                })
                .collect_vec();
            Some(serde_json::Value::Array(trimmed_vec))
        }
        Value::String(val_str) if value_is_same(&value) => {
            let dist_to_diff = *diff_map.borrow();
            if dist_to_diff <= config.level {
                Some(serde_json::Value::String(val_str))
            } else {
                None
            }
        }
        Value::String(val_str) => Some(serde_json::Value::String(val_str)),
        Value::Number(number) => Some(serde_json::Value::Number(number)),
        Value::Bool(bool_val) => Some(serde_json::Value::Bool(bool_val)),
        Value::Null => Some(Value::Null),
    }
}

fn trim_comparison(comparison: Value, config: &TrimConfig) -> Value {
    let diff_map = build_diff_map(&comparison);
    trim_value(comparison, &diff_map, config)
        .expect("Input comparison should result in Some value.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_minimal() {
        let obj = json!({
          "calldata": [
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
          ],
        });

        let expected_trimmed_obj = json!({
          "calldata": [
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
          ],
        });

        let config = TrimConfig { level: 1 };
        let trimmed_obj = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj, expected_trimmed_obj);
    }

    #[test]
    fn test_same() {
        let obj = json!({
          "first_element": "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
          "second_element":  {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
        });

        let expected_trimmed_obj = json!({
          "second_element":  {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
        });

        let config = TrimConfig { level: 0 };
        let trimmed_obj = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj, expected_trimmed_obj);
    }

    #[test]
    fn test_simple_2() {
        let obj = json!({
          "block_num": 647485,
          "calldata": [
            "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
            "Same(0x0)"
          ],
        });

        let expected_trimmed_obj = json!({
          "block_num": 647485,
          "calldata": [
            "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
            "Same(0x0)"
          ],
        });

        let config = TrimConfig { level: 2 };
        let trimmed_obj = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj, expected_trimmed_obj);
    }

    #[test]
    fn test_simple_0() {
        let obj = json!({
          "block_num": 647485,
          "calldata": [
            "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
            "Same(0x0)"
          ],
        });

        let expected_trimmed_obj = json!({
          "block_num": 647485,
          "calldata": [
            {
              "Different": {
                "base": "0x2863eece73692",
                "native": "0x16522c650ca4f"
              }
            },
          ],
        });

        let config = TrimConfig { level: 0 };
        let trimmed_obj = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj, expected_trimmed_obj);
    }

    #[test]
    fn test_long_array() {
        let obj = json!({
          "root" : [
            "Same({0})",
            "Same({1})",
            "Same({2})",
            "Same({3})",
            "Same({4})",
            "Same({5})",
            "Same({6})",
            "Same({7})",
            {
              "key": "Same(0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a)",
              "value": {
                "Different": {
                  "base": "0x20c632e33333b4c5",
                  "native": "0x20c62db4af3ea769"
                }
              }
            },
            "Same({9})",
            "Same({10})",
            "Same({11})",
            "Same({12})",
            "Same({13})",
            "Same({14})",
          ]
        });

        let expected_trimmed_obj = json!({
          "root" : [
            {
              "key": "Same(0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a)",
              "value": {
                "Different": {
                  "base": "0x20c632e33333b4c5",
                  "native": "0x20c62db4af3ea769"
                }
              }
            },
          ]
        });

        let config = TrimConfig { level: 1 };
        let trimmed_obj = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj, expected_trimmed_obj);
    }

    fn realistic_input() -> Value {
        json!({
          "num": 647485,
          "list": [
            {
              "a": "Same([0])",
              "b": "Same([0])",
              "c": {
                "1": "Same({12})",
                "2": {
                  "i": "Same(CALL)",
                  "ii": [
                    "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                    {
                      "Different": {
                        "base": "0x2863eece73692",
                        "native": "0x16522c650ca4f"
                      }
                    },
                    "Same(0x0)"
                  ],
                  "iii": "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                  "iv": [
                    {
                      "alpha": [
                        "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                        "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                        {
                          "Different": {
                            "base": "0x2863eece73692",
                            "native": "0x16522c650ca4f"
                          }
                        },
                        "Same(0x0)"
                      ],
                      "beta": "Same([1])",
                      "gamma": "Same(0)"
                    }
                  ],
                  "v": "Same({4})",
                  "vi": "Same([0])",
                },
                "3": "Same(INVOKE)",
                "4": "Same({12})"
              },
              "d": "0x27d408b6c916470a9ee999231c54f5cd3394b8c1552135ef2b4f6e4112c372b"
            },
          ]
        })
    }

    #[test]
    fn test_realistic_example_3() {
        let obj = realistic_input();
        let expected_trimmed_obj_3 = json!({
          "num": 647485,
          "list": [
            {
              "c": {
                "1": "Same({12})",
                "2": {
                  "i": "Same(CALL)",
                  "ii": [
                    "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                    {
                      "Different": {
                        "base": "0x2863eece73692",
                        "native": "0x16522c650ca4f"
                      }
                    },
                    "Same(0x0)"
                  ],
                  "iii": "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                  "iv": [
                    {
                      "alpha": [
                        "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                        "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                        {
                          "Different": {
                            "base": "0x2863eece73692",
                            "native": "0x16522c650ca4f"
                          }
                        },
                        "Same(0x0)"
                      ],
                      "beta": "Same([1])",
                      "gamma": "Same(0)"
                    }
                  ],
                  "v": "Same({4})",
                  "vi": "Same([0])",
                },
                "3": "Same(INVOKE)",
                "4": "Same({12})"
              },
              "d": "0x27d408b6c916470a9ee999231c54f5cd3394b8c1552135ef2b4f6e4112c372b"
            },
          ]
        });

        let config = TrimConfig { level: 3 };
        let trimmed_obj_3 = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj_3, expected_trimmed_obj_3);
    }

    #[test]
    fn test_realistic_example_2() {
        let obj = realistic_input();
        let expected_trimmed_obj_2 = json!({
          "num": 647485,
          "list": [
            {
              "c": {
                "2": {
                  "i": "Same(CALL)",
                  "ii": [
                    "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                    {
                      "Different": {
                        "base": "0x2863eece73692",
                        "native": "0x16522c650ca4f"
                      }
                    },
                    "Same(0x0)"
                  ],
                  "iii": "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                  "iv": [
                    {
                      "alpha": [
                        "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                        "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                        {
                          "Different": {
                            "base": "0x2863eece73692",
                            "native": "0x16522c650ca4f"
                          }
                        },
                        "Same(0x0)"
                      ],
                      "beta": "Same([1])",
                      "gamma": "Same(0)"
                    }
                  ],
                  "v": "Same({4})",
                  "vi": "Same([0])",
                },
              },
              "d": "0x27d408b6c916470a9ee999231c54f5cd3394b8c1552135ef2b4f6e4112c372b"
            },
          ]
        });

        let config = TrimConfig { level: 2 };
        let trimmed_obj_2 = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj_2, expected_trimmed_obj_2);
    }

    #[test]
    fn test_realistic_example_1() {
        let obj = realistic_input();
        let expected_trimmed_obj_1 = json!({
          "num": 647485,
          "list": [
            {
              "c": {
                "2": {
                  "ii": [
                    "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                    {
                      "Different": {
                        "base": "0x2863eece73692",
                        "native": "0x16522c650ca4f"
                      }
                    },
                    "Same(0x0)"
                  ],
                  "iv": [
                    {
                      "alpha": [
                        "Same(0x68b46e93659576c77a30d941648b8deacd38c12aad2336f4bace7ce75c6d9a)",
                        "Same(0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8)",
                        {
                          "Different": {
                            "base": "0x2863eece73692",
                            "native": "0x16522c650ca4f"
                          }
                        },
                        "Same(0x0)"
                      ],
                    }
                  ],
                },
              },
              "d": "0x27d408b6c916470a9ee999231c54f5cd3394b8c1552135ef2b4f6e4112c372b"
            },
          ]
        });

        let config = TrimConfig { level: 1 };
        let trimmed_obj_1 = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj_1, expected_trimmed_obj_1);
    }

    #[test]
    fn test_realistic_example_0() {
        let obj = realistic_input();
        let expected_trimmed_obj_0 = json!({
          "num": 647485,
          "list": [
            {
              "c": {
                "2": {
                  "ii": [
                    {
                      "Different": {
                        "base": "0x2863eece73692",
                        "native": "0x16522c650ca4f"
                      }
                    },
                  ],
                  "iv": [
                    {
                      "alpha": [
                        {
                          "Different": {
                            "base": "0x2863eece73692",
                            "native": "0x16522c650ca4f"
                          }
                        },
                      ],
                    }
                  ],
                },
              },
              "d": "0x27d408b6c916470a9ee999231c54f5cd3394b8c1552135ef2b4f6e4112c372b"
            },
          ]
        });

        let config = TrimConfig { level: 0 };
        let trimmed_obj_0 = trim_comparison(obj, &config);
        assert_eq!(trimmed_obj_0, expected_trimmed_obj_0);
    }
}
