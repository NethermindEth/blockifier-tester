use crate::trace_comparison::{
    BlockTraceComparison, BlockTraceResult, InnerCallComparison, InvokeComparison,
};

use glob::glob;
use itertools::Itertools;
use log::{info, warn};
use num_bigint::BigUint;
use rctree::{self, Node};
use starknet::core::types::FieldElement;
use std::{collections::HashMap, fs::OpenOptions, io::Write, path::Path};

pub fn dump() {
    let out_dir = Path::new("./out");

    let mut top_level_calls: Vec<TransactionCall> = vec![];
    for entry in glob("./results/trace-*").expect("failed to glob results") {
        match entry {
            Ok(path) => {
                info!("reading {}", path.to_str().unwrap());
                let new_calls = read_top_level_calls(path.as_path());
                for call in new_calls.into_iter() {
                    if !&call.inner_call.has_children() {
                        top_level_calls.push(call)
                    }
                }
            }
            Err(err) => warn!("glob err: '{err:?}'"),
        }
    }

    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("filtered.csv"))
        .expect("Failed to open log file");

    let out_table = top_level_calls
        .iter()
        .map(|call| call.to_vec())
        .collect_vec();
    let _ = writeln!(log_file, "{}", get_header_vec(out_table).join(", "));
    for call in top_level_calls.iter() {
        if let Err(write_err) = writeln!(log_file, "{}", call.to_vec().join(", ")) {
            warn!("Failed to write err with error: '{write_err}'");
        }
    }

    // Print calls by category.
    let categorized = CategorizedCalls::from_calls(top_level_calls.iter());

    let mut log_by_transactions = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("filtered_by_transactions.log"))
        .expect("Failed to open log file");
    for (key, value) in categorized.by_transactions.iter() {
        let _ = writeln!(log_by_transactions, "{}, {}", key, value.len());
    }

    let mut log_by_contract = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("filtered_by_contract.log"))
        .expect("Failed to open log file");
    for (key, value) in categorized.by_contract.iter() {
        let _ = writeln!(
            log_by_contract,
            "{}, {}",
            felt_to_hex(key, true),
            value.len()
        );
    }

    let mut log_by_contract_selector = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_dir.join("filtered_by_contract_selector.log"))
        .expect("Failed to open log file");
    for (key, value) in categorized.by_contract_selector.iter() {
        let _ = writeln!(
            log_by_contract_selector,
            "{}, {}, {}",
            felt_to_hex(&key.0, true),
            felt_to_hex(&key.1, true),
            value.len()
        );
    }
}

#[derive(Clone)]
pub struct TransactionCall {
    transaction_hash: String,
    inner_call: Node<InnerCall>,
}

fn get_header_vec(table: Vec<Vec<String>>) -> Vec<&'static str> {
    match table.iter().max() {
        Some(longest_column) => {
            // First column headers.
            vec!["transaction", "contract", "selector"]
                .into_iter()
                .chain(
                    // The rest of the columns are: contract, selector
                    (0..longest_column.len().saturating_sub(3)).map(|index| match index % 2 {
                        0 => "contract",
                        _ => "selector",
                    }),
                )
                .take(longest_column.len())
                .collect_vec()
        }
        None => vec![],
    }
}

impl TransactionCall {
    fn to_vec(&self) -> Vec<String> {
        let mut fields = vec![
            self.transaction_hash.clone(),
            felt_to_hex(&self.inner_call.borrow().contract, true),
            felt_to_hex(&self.inner_call.borrow().selector, true),
        ];

        let in_order_parents = self
            .inner_call
            .ancestors()
            .skip(1)
            .map(|node| node.borrow().to_tuple())
            .collect_vec()
            .into_iter()
            .rev()
            .collect_vec();

        let in_order_children = self
            .inner_call
            .descendants()
            .skip(1)
            .map(|node| node.borrow().to_tuple())
            .collect_vec();

        for item in in_order_parents
            .into_iter()
            .chain(Some(self.inner_call.borrow().to_tuple()).into_iter())
            .chain(in_order_children)
        {
            fields.push(item.0);
            fields.push(item.1);
        }
        fields
    }
}

#[derive(Clone)]
pub struct InnerCall {
    contract: FieldElement,
    selector: FieldElement,
}

impl InnerCall {
    fn to_tuple(&self) -> (String, String) {
        (
            felt_to_hex(&self.contract, true),
            felt_to_hex(&self.selector, true),
        )
    }
}

fn push_or_add<K, T, S>(map: &mut HashMap<K, Vec<T>, S>, key: K, value: T)
where
    K: std::hash::Hash + Eq + PartialEq,
    S: std::hash::BuildHasher,
{
    let option = map.get_mut(&key);
    match option {
        None => {
            map.insert(key, vec![value]);
        }
        Some(elem) => {
            elem.push(value);
        }
    }
}

struct CategorizedCalls {
    by_transactions: HashMap<String, Vec<TransactionCall>>,
    by_contract: HashMap<FieldElement, Vec<TransactionCall>>,
    by_contract_selector: HashMap<(FieldElement, FieldElement), Vec<TransactionCall>>,
}
impl CategorizedCalls {
    fn from_calls<'a, T>(calls: T) -> Self
    where
        T: Iterator<Item = &'a TransactionCall>,
    {
        let mut by_transactions = HashMap::<String, Vec<TransactionCall>>::new();
        let mut by_contract = HashMap::<FieldElement, Vec<TransactionCall>>::new();
        let mut by_contract_selector =
            HashMap::<(FieldElement, FieldElement), Vec<TransactionCall>>::new();
        for call in calls {
            push_or_add(
                &mut by_transactions,
                call.transaction_hash.clone(),
                call.clone(),
            );
            push_or_add(
                &mut by_contract,
                call.inner_call.borrow().contract,
                call.clone(),
            );
            push_or_add(
                &mut by_contract_selector,
                (
                    call.inner_call.borrow().contract,
                    call.inner_call.borrow().selector,
                ),
                call.clone(),
            );
        }
        Self {
            by_transactions,
            by_contract,
            by_contract_selector,
        }
    }
}

fn read_top_level_calls(path: &Path) -> Vec<TransactionCall> {
    let log_file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .expect("Failed to open log file");

    //  BlockTraceComparison
    let result: BlockTraceResult =
        serde_json::from_reader(log_file).expect("failed to read comparison file");
    info!("block: {}", result.block_number);
    get_top_level_calls(result.comparison)
}

fn get_top_level_calls(block_trace_comparison: BlockTraceComparison) -> Vec<TransactionCall> {
    match block_trace_comparison {
        BlockTraceComparison::BothSucceeded {
            transaction_traces: trace_comparisons,
        } => {
            trace_comparisons
                .iter()
                .filter_map(|comparison| {
                    match comparison {
                        crate::trace_comparison::TransactionTraceComparison::Both {
                            transaction_hash,
                            body:
                                crate::trace_comparison::TransactionTraceComparisonBody::Invoke(
                                    invocation_comparison,
                                ),
                        } => build_inner_calls(invocation_comparison).map(|calls| {
                            calls
                                .iter()
                                .map(|inner_call| TransactionCall {
                                    transaction_hash: transaction_hash.clone(),
                                    inner_call: inner_call.clone(),
                                })
                                .collect_vec()
                        }), // Comparison::Both
                        _ => None,
                    }
                }) // filter map
                .flatten()
                .collect_vec()
        }
        BlockTraceComparison::BaseFailed(_) => vec![],
        BlockTraceComparison::NativeFailed(_) => vec![],
        BlockTraceComparison::BothFailed {
            base_error: _,
            native_error: _,
        } => vec![],
    }
}

fn build_inner_calls(comparison: &InvokeComparison) -> Option<Vec<Node<InnerCall>>> {
    match comparison {
        InvokeComparison::BothSucceeded {
            results,
            inner_calls,
        } => match results {
            crate::trace_comparison::CallResultComparison::Same => None, // TODO add back in to innerCall struct?
            crate::trace_comparison::CallResultComparison::Different { base: _, native: _ } => {
                Some(
                    inner_calls
                        .iter()
                        .map(|inner_comparison| {
                            let this_node = Node::new(InnerCall {
                                contract: inner_comparison.contract,
                                selector: inner_comparison.selector,
                            });
                            for node in _build_inner_calls(inner_comparison) {
                                this_node.append(node)
                            }
                            this_node
                        })
                        // .flatten()
                        .collect(),
                )
            }
        },
        _ => None,
    }
}

fn _build_inner_calls(comparison: &InnerCallComparison) -> Vec<Node<InnerCall>> {
    match &comparison.info {
        crate::trace_comparison::InnerCallComparisonInfo::Different {
            inner_calls,
            base: _,
            native: _,
        } => inner_calls
            .iter()
            .map(|inner_call_comparison| {
                let inner_call = Node::new(InnerCall {
                    contract: inner_call_comparison.contract,
                    selector: inner_call_comparison.selector,
                });
                for child in _build_inner_calls(inner_call_comparison) {
                    inner_call.append(child);
                }
                inner_call
            })
            .collect(),
        _ => vec![],
    }
}

// TODO this is a duplicate method with trace_comparison.rs
fn felt_to_hex(value: &FieldElement, with_prefix: bool) -> String {
    match with_prefix {
        true => format!("0x{}", felt_to_hex(value, false)),
        false => BigUint::from_bytes_be(&value.to_bytes_be()).to_str_radix(16),
    }
}
