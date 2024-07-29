use anyhow::Context;
use itertools::Itertools;
use log::{info, warn};
use num_bigint::BigUint;
use petgraph::visit::Walker;
use starknet::core::types::{ContractStorageDiffItem, FieldElement, TransactionTraceWithHash};
use std::io::Write;
use std::{collections::HashMap, fs::OpenOptions, path::Path};

use petgraph::{
    graph::{Graph, NodeIndex},
    visit::Dfs,
};

fn get_state_diff_addresses(
    transaction_trace: &TransactionTraceWithHash,
) -> Option<Vec<ContractStorageDiffItem>> {
    match &transaction_trace.trace_root {
        starknet::core::types::TransactionTrace::Invoke(invoke) => invoke
            .state_diff
            .as_ref()
            .map(|diffs| diffs.storage_diffs.clone()),
        starknet::core::types::TransactionTrace::L1Handler(layer_1) => layer_1
            .state_diff
            .as_ref()
            .map(|diffs| diffs.storage_diffs.clone()),
        starknet::core::types::TransactionTrace::Declare(declare) => declare
            .state_diff
            .as_ref()
            .map(|diffs| diffs.storage_diffs.clone()),
        starknet::core::types::TransactionTrace::DeployAccount(deploy) => deploy
            .state_diff
            .as_ref()
            .map(|diffs| diffs.storage_diffs.clone()),
    }
}

#[allow(dead_code)]
fn read_block_transactions(
    block_number: u64,
    branch: &str,
) -> Result<Vec<TransactionTraceWithHash>, anyhow::Error> {
    let path_str = &format!("./dump/trace-{block_number}-{branch}.json");
    let path = Path::new(path_str);

    let log_file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .context(path.to_str().unwrap().to_string())?;
    Ok(serde_json::from_reader(log_file).expect("failed to read comparison file"))
}

/// Used for building dependency graphs for transactions.
/// Contains helper objects to track previous entries for building the dependency graph.
#[derive(Default)]
struct TransactionGraph<K> {
    // Each node represents a transaction. Each edge represents a statement that the nodes both have the same diff. The direction of the edge is the reverse order of the transactions in the block.
    // For example: An edge from B to A implies "B may depend on A" or "A modifies the K that later B modifies". When K is a ContractStorageDiffItem.address, this would imply that A has a StorageDiffItem with the same address as B, and A precedes B in the block.
    graph: Graph<FieldElement, i32>,
    // Maps key type `K` to transaction hashes.
    transaction_map: HashMap<K, Vec<FieldElement>>,
    // Maps transaction_hash to node indices.
    node_indices: HashMap<FieldElement, NodeIndex>,
}
impl<K> TransactionGraph<K>
where
    K: Eq + std::hash::Hash,
{
    /// Add a node representing a transaction to the graph and ensure it exists in the node_indecies map.
    fn add(&mut self, transaction: &TransactionTraceWithHash) -> NodeIndex {
        let curr_node = self.graph.add_node(transaction.transaction_hash);
        *self
            .node_indices
            .entry(transaction.transaction_hash)
            .or_insert(curr_node)
    }

    /// Process `key` of `transaction`.
    ///
    /// Assumptions:
    ///
    /// 1. The `key` should be a `K` found in the transaction. For example: If `K` is `ContractStorageDiffItem.address`, then the `key` should be a `ContractStorageDiffItem.address` in `transaction`.
    /// 2. The `transaction` has been added using `add`, and thus has been added to the graph as a node and to the indices map.
    ///
    /// Actions:
    ///
    /// 1. Checks for previous transactions that have been processed with the same `key`. For each of these transactions, an edge is added from this `transaction` (the one passed in) to the previous transaction (the one that has already been processed with this `key`). For example: If `K` is `ContractStorageDiffItem.address`, this represents that the previous transactions (nodes) have `ContractStorageDiffItem`s with the same `.address`s as this `transaction`'s `ContractStorageDiffItem.address` (the given `key`).
    /// 2. Adds this `transaction` to the list of previous transactions that have been processed with `key`. Now, if `process_item` is called on the same `key`, this `transaction` will found by step 1.
    fn process_item(
        &mut self,
        curr_node: NodeIndex,
        key: K,
        transaction: &TransactionTraceWithHash,
    ) {
        // Have any previous transactions seen this `key`?
        // For example: Does any previous transaction have this `StateDiff.address`?
        if let Some(prev_transactions) = self.transaction_map.get(&key) {
            for prev_transaction in prev_transactions {
                let prev_node = self.node_indices.get(prev_transaction).expect(
                    "Transaction was found in previous diff, but failed to find its matching Node",
                );
                self.graph.add_edge(curr_node, *prev_node, 1);
            }
        }
        // Add this `transaction` to the map of `key`s to previous `transaction`s so it can be found next time.
        self.transaction_map
            .entry(key)
            .or_default()
            .push(transaction.transaction_hash);
    }
}

/// Contains graphs for contract diff address dependencies and diff storage key dependencies.
/// Also provides convinience function for processing `ContractStorageDiffItem`s for both `TransactionGraph`s.
#[derive(Default)]
struct TransactionDiffStore {
    // Transaction graph using `ContractStorageDiffItem.address` as the `key`.
    // Maps `ContractStorageDiffItem.address` to `transaction_hash`s.
    contract_graph: TransactionGraph<FieldElement>,

    // Transaction graph using `ContractStorageDiffItem.address`+`StorageEntry.key` as the `key`.
    // Maps every `ContractStorageDiffItem.address`+`StorageEntry.key` in every ContractStorageDiffItem to `transaction_hash`s.
    storage_key_graph: TransactionGraph<(FieldElement, FieldElement)>,
}
impl TransactionDiffStore {
    /// Processes each `ContractStorageDiffItem` in `transaction.storage_diffs`.
    ///
    /// For `self.contract_graph`, processes each `ContractStorageDiffItem.address`.
    ///
    /// For `self.storage_key_graph`, processes each `(ContractStorageDiffItem.address, StorageEntry.key)` for each `StorageEntry` in each `ContractStorageDiffItem`.
    fn process_transaction(
        &mut self,
        transaction: &TransactionTraceWithHash,
    ) -> Result<(), anyhow::Error> {
        let contract_node = self.contract_graph.add(transaction);
        let storage_key_node = self.storage_key_graph.add(transaction);
        if let Some(diff_items) = get_state_diff_addresses(transaction) {
            self.process_diff_items(
                contract_node,
                storage_key_node,
                diff_items.into_iter(),
                transaction,
            );
            Ok(())
        } else {
            Err(
                anyhow::format_err!("storage_diffs not found for transaction").context(format!(
                    "transaction: {}",
                    felt_to_hex(&transaction.transaction_hash, true)
                )),
            )
        }
    }

    fn process_diff_items<T>(
        &mut self,
        contract_node: NodeIndex,
        storage_key_node: NodeIndex,
        diff_items: T,
        transaction: &TransactionTraceWithHash,
    ) where
        T: Iterator<Item = ContractStorageDiffItem>,
    {
        for diff_item in diff_items {
            self.contract_graph
                .process_item(contract_node, diff_item.address, transaction);
            for storage_entry in diff_item.storage_entries {
                self.storage_key_graph.process_item(
                    storage_key_node,
                    (diff_item.address, storage_entry.key),
                    transaction,
                );
            }
        }
    }
}

#[allow(dead_code)]
pub fn write_transaction_dependencies<'a, T>(
    block_num: u64,
    branch: &str,
    transactions: T,
) -> Result<(), anyhow::Error>
where
    T: Iterator<Item = &'a TransactionTraceWithHash>,
{
    info!("Dumping transaction dependencies for block '{block_num}' on branch '{branch}'");
    let (contract_graph, storage_graph) = make_graphs(transactions);

    let contracts_path_string =
        format!("./results/dependencies/transaction_contracts-{block_num}-{branch}.log");
    let transaction_contracts_path = Path::new(contracts_path_string.as_str());
    let storage_path_string =
        format!("./results/dependencies/transaction_storage-{block_num}-{branch}.log");
    let transaction_storage_path = Path::new(storage_path_string.as_str());

    let log_result_1 =
        log_graph(transaction_contracts_path, contract_graph).inspect_err(|err| warn!("{err:?}"));
    let log_result_2 =
        log_graph(transaction_storage_path, storage_graph).inspect_err(|err| warn!("{err:?}"));
    log_result_1.and(log_result_2)
}

pub fn log_graph(path: &Path, graph: Graph<FieldElement, i32>) -> Result<(), anyhow::Error> {
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context(format!(
            "Logging graph to path: {:?}",
            path.to_str().unwrap()
        ))?;
    let mut out_list: Vec<Vec<String>> = graph_to_vecs(graph);
    // Show transactions with the least dependencies first.
    out_list.sort_by_key(|row| row.len());
    for row in out_list {
        writeln!(log_file, "{}", row.join(", "))?
    }
    Ok(())
}

pub type DependencyMap = HashMap<FieldElement, Vec<String>>;

/// Get hashmap of dependencies for transactions.
///
/// Returns: Tuple of Hashmaps with `transaction_hash` as keys and `Vec` of `transaction_hash` hex strings as values.
/// The first hashmap contains contract dependencies. The second hashmap contains storage dependencies.
///
/// Hashmap keys: A `transaction_hash` for each transaction in `block_transactions`.
///
/// Hashmap values: A list of `transaction_hash`s for each transaction depended on by the transaction of the corresponding key.
/// For example, the key value pair: `(4, [1, 2])` implies that transaction 4 depends on transactions 1 and 2.
pub fn get_dependencies<'a, T>(block_transactions: T) -> (DependencyMap, DependencyMap)
where
    T: Iterator<Item = &'a TransactionTraceWithHash>,
{
    let (contract_graph, storage_graph) = make_graphs(block_transactions);
    (graph_to_map(contract_graph), graph_to_map(storage_graph))
}

fn make_graphs<'a, T>(block_transactions: T) -> (Graph<FieldElement, i32>, Graph<FieldElement, i32>)
where
    T: Iterator<Item = &'a TransactionTraceWithHash>,
{
    let mut transaction_map: TransactionDiffStore = Default::default();
    for transaction in block_transactions {
        let _ = transaction_map
            .process_transaction(transaction)
            .inspect_err(|err| warn!("{err:?}"));
    }
    (
        transaction_map.contract_graph.graph,
        transaction_map.storage_key_graph.graph,
    )
}

/// For each node in the graph, maps the node to all values from a DFS traversal of the node.
fn graph_to_map(graph: Graph<FieldElement, i32>) -> HashMap<FieldElement, Vec<String>> {
    let mut table = HashMap::<FieldElement, Vec<String>>::new();
    for start_node in graph.node_indices() {
        let key = graph[start_node];
        // Note: The first node in each DFS is always the start_node, so it is skipped for the hash value.
        let row = Dfs::new(&graph, start_node)
            .iter(&graph)
            .skip(1)
            .map(|node| felt_to_hex(&graph[node], true))
            .collect_vec();
        table.entry(key).or_insert(row);
    }
    table
}

/// For each node in the graph, creates vector with all values from a DFS traversal of the node.
fn graph_to_vecs(graph: Graph<FieldElement, i32>) -> Vec<Vec<String>> {
    let mut table = vec![];
    for start_node in graph.node_indices() {
        // Note: The first node in each DFS is always the start_node, so we don't need to prepend start_node.
        let row = Dfs::new(&graph, start_node)
            .iter(&graph)
            .map(|node| felt_to_hex(&graph[node], true))
            .collect_vec();
        table.push(row);
    }
    table
}

fn felt_to_hex(value: &FieldElement, with_prefix: bool) -> String {
    match with_prefix {
        true => format!("0x{}", felt_to_hex(value, false)),
        false => BigUint::from_bytes_be(&value.to_bytes_be()).to_str_radix(16),
    }
}

#[cfg(test)]
mod tests {
    use itertools::assert_equal;

    use super::*;
    use starknet::core::types::{
        CallType, EntryPointType, ExecutionResources, FunctionInvocation, StateDiff, StorageEntry,
        TransactionTrace,
    };

    struct StarknetDummyFactory {}
    impl StarknetDummyFactory {
        // Read fn as "test_{fn}_dependencies". Also "keys" => "`storage_diff.key`s".
        // no_contract => test_no_contract_dependencies.

        /// Wrapper for iterable over `Self::transaction_trace`.
        ///
        /// Type Params:
        ///
        /// `transactions` : Iterable of (transaction_hash : `FieldLike`, storage_diffs : `DiffsIterable`)
        fn transaction_traces<TransactionIterable, DiffsIterable, FieldLikeIterable, FieldLike>(
            transactions: TransactionIterable,
        ) -> Vec<TransactionTraceWithHash>
        where
            TransactionIterable: IntoIterator<Item = (FieldLike, DiffsIterable)>,
            DiffsIterable: IntoIterator<Item = (FieldLike, FieldLikeIterable)>,
            FieldLikeIterable: IntoIterator<Item = FieldLike>,
            FieldLike: Into<FieldElement>,
        {
            transactions
                .into_iter()
                .map(|(transaction_hash, diffs)| Self::transaction_trace(transaction_hash, diffs))
                .collect_vec()
        }

        fn invocation() -> FunctionInvocation {
            let dummy_resources = ExecutionResources {
                steps: 0,
                memory_holes: None,
                range_check_builtin_applications: None,
                pedersen_builtin_applications: None,
                poseidon_builtin_applications: None,
                ec_op_builtin_applications: None,
                ecdsa_builtin_applications: None,
                bitwise_builtin_applications: None,
                keccak_builtin_applications: None,
                segment_arena_builtin: None,
            };

            let dummy_field = FieldElement::from(0_u32);
            FunctionInvocation {
                contract_address: dummy_field,
                entry_point_selector: dummy_field,
                calldata: vec![],
                caller_address: dummy_field,
                class_hash: dummy_field,

                entry_point_type: EntryPointType::External,
                call_type: CallType::Call,

                result: vec![],
                calls: vec![],
                events: vec![],
                messages: vec![],

                execution_resources: dummy_resources,
            }
        }

        fn state_diff(storage_diffs: Vec<ContractStorageDiffItem>) -> StateDiff {
            StateDiff {
                storage_diffs,
                deprecated_declared_classes: vec![],
                declared_classes: vec![],
                deployed_contracts: vec![],
                replaced_classes: vec![],
                nonces: vec![],
            }
        }

        fn transaction_trace_with_none<FieldLike>(
            transaction_hash: FieldLike,
        ) -> TransactionTraceWithHash
        where
            FieldLike: Into<FieldElement>,
        {
            Self::transaction_trace_from_state_diff(transaction_hash, None)
        }

        /// Creates a TransactionTraceWithHash with the given `transaction_hash` and `storage_diffs` (keys only) and dummy values for everything else.
        /// Inputs:
        ///
        /// `transaction_hash` : `transaction_hash` to plug into the resulting `TransactionTraceWithHash`.
        ///
        /// `storage_diffs` : Iterable of (contract_hash : `FieldLike`, diff_keys : `FieldLikeIterable`).
        /// For example: `[(41_u32, [0_u32, 1_u32, 2_u32]), (42_u32, [0_u32, 3_u32])]` represents two `ContractStorageDiffItem`s.
        /// The first represents a `ContractStorageDiffItem` at the contract address `41_u32` and with three `StorageEntry`s with the keys: 0_u32, 1_u32, and 2_u32.
        /// The second represents a `ContractStorageDiffItem` at the contract address `42_u32` and with two `StorageEntry`s with the keys: 0_u32 and 3_u32.
        ///
        /// Type Params:
        ///
        /// `DiffsIterable` : Iterable of (contract_hash : `FieldLike`, diff_keys : `FieldLikeIterable`).
        ///
        /// `FieldLikeIterable` : Iterable of `FieldLike`.
        ///
        /// `FieldLike` : An object that can be converted to a `FieldElement` with `Into<FieldElement`.
        fn transaction_trace<DiffsIterable, FieldLikeIterable, FieldLike>(
            transaction_hash: FieldLike,
            storage_diffs: DiffsIterable,
        ) -> TransactionTraceWithHash
        where
            DiffsIterable: IntoIterator<Item = (FieldLike, FieldLikeIterable)>,
            FieldLikeIterable: IntoIterator<Item = FieldLike>,
            FieldLike: Into<FieldElement>,
        {
            let diffs = storage_diffs
                .into_iter()
                .map(|(contract, storage_entries)| ContractStorageDiffItem {
                    address: contract.into(),
                    storage_entries: storage_entries
                        .into_iter()
                        .map(|key| StorageEntry {
                            key: key.into(),
                            value: FieldElement::from(0_u32),
                        })
                        .collect_vec(),
                })
                .collect_vec();

            let state_diff = Self::state_diff(diffs);
            Self::transaction_trace_from_state_diff(transaction_hash, Some(state_diff))
        }

        fn transaction_trace_from_state_diff<FieldLike>(
            transaction_hash: FieldLike,
            state_diff: Option<StateDiff>,
        ) -> TransactionTraceWithHash
        where
            FieldLike: Into<FieldElement>,
        {
            let dummy_invocation = Self::invocation();

            let dummy_invoke_transaction_trace = starknet::core::types::InvokeTransactionTrace {
                validate_invocation: None,
                execute_invocation: starknet::core::types::ExecuteInvocation::Success(
                    dummy_invocation,
                ),
                fee_transfer_invocation: None,
                state_diff,
            };

            TransactionTraceWithHash {
                transaction_hash: transaction_hash.into(),
                trace_root: TransactionTrace::Invoke(dummy_invoke_transaction_trace),
            }
        }
    }

    type Dummy = StarknetDummyFactory;

    /// Converts an Iterable of Iterable of an Item that can be converted to a `FieldElement` to a `Vec<Vec<String>>`
    /// by converting the inner items to `FieldElement`s and then converting the `FieldElement` to a hex string.
    ///
    /// For example, converts Vec<Vec<u32>> to Vec<Vec<String>>.
    /// Each `u32` will be converted to `FieldElement` and then `String` using `felt_to_hex`.
    fn convert_inner<Feltable, Iterable, InnerIterable>(iterable: Iterable) -> Vec<Vec<String>>
    where
        Iterable: IntoIterator<Item = InnerIterable>,
        InnerIterable: IntoIterator<Item = Feltable>,
        FieldElement: From<Feltable>,
    {
        iterable
            .into_iter()
            .map(|inner_vec| {
                inner_vec
                    .into_iter()
                    .map(|item| felt_to_hex(&FieldElement::from(item), true))
                    .collect_vec()
            })
            .collect_vec()
    }

    fn test_graph_transactions<Feltable>(
        transactions: Vec<TransactionTraceWithHash>,
        expected_contracts: Vec<Vec<Feltable>>,
        expected_storages: Vec<Vec<Feltable>>,
    ) where
        FieldElement: From<Feltable>,
    {
        let (contract_graph, storage_graph) = make_graphs(transactions.iter());
        let contract_dependencies: Vec<Vec<String>> = graph_to_vecs(contract_graph);
        let storage_dependencies: Vec<Vec<String>> = graph_to_vecs(storage_graph);

        let expected_contracts: Vec<Vec<String>> = convert_inner(expected_contracts);
        let expected_storages: Vec<Vec<String>> = convert_inner(expected_storages);
        assert_equal(contract_dependencies, expected_contracts);
        assert_equal(storage_dependencies, expected_storages);
    }

    /// Given: A TransactionDiffStore and a Transactions with `state_diff` that is `None`.
    /// When: Processing the transaction.
    /// Then: Return an error.
    #[test]
    fn process_state_diff_none() {
        let mut transaction_map: TransactionDiffStore = Default::default();
        let transactions = vec![
            Dummy::transaction_trace(1_u32, [(1_u32, [1_u32])]),
            Dummy::transaction_trace_with_none(2_u32),
            Dummy::transaction_trace(3_u32, [(2_u32, [2_u32])]),
        ];

        let mut results = vec![];
        for transaction in transactions.iter() {
            results.push(transaction_map.process_transaction(transaction));
        }

        assert_equal(results.into_iter().map(|r| r.is_ok()), [true, false, true]);
    }

    /// Scenario: Mapping transactions dependencies.
    mod mapping_transaction_dependencies {
        use super::*;

        /// Given: Transactions with multiple overlapping contracts.
        /// Then: Result should show dependency between later transaction and ealier transaction.
        #[test]
        fn graph_multiple_contract_dependencies() {
            let (transaction_1, transaction_2, transaction_3, transaction_4) =
                (1_u32..5_u32).collect_tuple().unwrap();
            let (contract_a, contract_b, contract_c) = (10_u32..13_u32).collect_tuple().unwrap();
            let key_alpha = 100_u32;

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (transaction_2, vec![(contract_b, [key_alpha])]),
                (transaction_3, vec![(contract_c, [key_alpha])]),
                (
                    transaction_4,
                    vec![(contract_a, [key_alpha]), (contract_c, [key_alpha])],
                ),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Bα
            // Transaction 3 modifies contract Cα
            // Transaction 4 modifies contract Aα, Cα

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: None
            // Transaction 3: None
            // Transaction 4: 1, 3

            // Expected storage dependencies:
            // Same

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4, transaction_1, transaction_3],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4, transaction_1, transaction_3],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // No contract dependencies
        /// Given: Transactions with no overlapping contracts.
        /// Then: Transactions should exist in output, but there should be no dependencies.
        #[test]
        fn no_contract() {
            let (transaction_1, transaction_2, transaction_3, transaction_4) =
                (1_u32..5_u32).collect_tuple().unwrap();
            let (
                contract_a,
                contract_b,
                contract_c,
                contract_d,
                contract_e,
                contract_f,
                contract_g,
            ) = (10_u32..17_u32).collect_tuple().unwrap();
            let key_alpha = 100_u32;

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (
                    transaction_2,
                    vec![(contract_b, [key_alpha]), (contract_c, [key_alpha])],
                ),
                (transaction_3, vec![(contract_d, [key_alpha])]),
                (
                    transaction_4,
                    vec![
                        (contract_e, [key_alpha]),
                        (contract_f, [key_alpha]),
                        (contract_g, [key_alpha]),
                    ],
                ),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Bα, Cα
            // Transaction 3 modifies contract Dα
            // Transaction 4 modifies contract Eα, Fα, Gα

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: None
            // Transaction 3: None
            // Transaction 4: None

            // Expected storage dependencies:
            // Same

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // No transactions (empty vec)
        /// Given: A vector of no transactions.
        /// Then: Result should have no transactions or dependencies.
        #[test]
        fn empty() {
            let transactions: Vec<TransactionTraceWithHash> = vec![];
            let expected_contract_dependencies: Vec<Vec<u32>> = vec![];
            let expected_storage_dependencies: Vec<Vec<u32>> = vec![];
            test_graph_transactions(
                transactions,
                expected_contract_dependencies,
                expected_storage_dependencies,
            );
        }

        // One transaction
        /// Given: A single transaction.
        /// Then: Result should have a single transaction and no dependencies.
        #[test]
        fn one_transaction() {
            let (contract_a, contract_b, contract_c) = (10_u32..13_u32).collect_tuple().unwrap();
            let key_alpha = 100_u32;
            let input = [
                (contract_a, [key_alpha]),
                (contract_b, [key_alpha]),
                (contract_c, [key_alpha]),
            ];

            let transactions: Vec<TransactionTraceWithHash> =
                vec![Dummy::transaction_trace(1_u32, input)];
            let expected_contract_dependencies: Vec<Vec<u32>> = vec![vec![1_u32]];
            let expected_storage_dependencies: Vec<Vec<u32>> = vec![vec![1_u32]];
            test_graph_transactions(
                transactions,
                expected_contract_dependencies,
                expected_storage_dependencies,
            );
        }

        // Contract dependencies and storage keys dependencies that are the same
        #[test]
        fn contract_and_keys_same() {
            let (transaction_1, transaction_2, transaction_3, transaction_4, transaction_5) =
                (1_u32..6_u32).collect_tuple().unwrap();
            let (contract_a, contract_b, contract_c, contract_d, contract_e) =
                (10_u32..15_u32).collect_tuple().unwrap();
            let (key_alpha, key_beta, key_gamma, key_delta, key_epsilon) =
                (100_u32..105_u32).collect_tuple().unwrap();

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (
                    transaction_2,
                    vec![(contract_b, [key_beta]), (contract_c, [key_gamma])],
                ),
                (transaction_3, vec![(contract_d, [key_delta])]),
                (
                    transaction_4,
                    vec![
                        (contract_e, [key_epsilon]),
                        (contract_c, [key_gamma]),
                        (contract_a, [key_alpha]),
                    ],
                ),
                (
                    transaction_5,
                    vec![(contract_e, [key_epsilon]), (contract_d, [key_delta])],
                ),
            ];

            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Bβ, Cγ
            // Transaction 3 modifies contract Dδ
            // Transaction 4 modifies contract Eε, Cγ, Aα
            // Transaction 5 modifies contract Eε, Dδ

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: None
            // Transaction 3: None
            // Transaction 4: 2, 1
            // Transaction 5: 4, 2, 1, 3

            // Expected storage dependencies:
            // Same

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4, transaction_2, transaction_1],
                vec![
                    transaction_5,
                    transaction_4,
                    transaction_2,
                    transaction_1,
                    transaction_3,
                ],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
                vec![transaction_4, transaction_2, transaction_1],
                vec![
                    transaction_5,
                    transaction_4,
                    transaction_2,
                    transaction_1,
                    transaction_3,
                ],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // Contract dependencies and storage keys dependencies that are different
        /// Given: Transactions that modify the same contracts, but not the same keys in the contracts.
        /// Then: Result should show dependencies in contracts, but not StorageEntry dependencies.
        #[test]
        fn contract_and_keys_diff() {
            let (transaction_1, transaction_2, transaction_3, transaction_4) =
                (1_u32..5_u32).collect_tuple().unwrap();
            let (contract_a, contract_b, contract_c) = (10_u32..13_u32).collect_tuple().unwrap();
            let (key_alpha, key_beta, key_gamma, key_delta, key_epsilon) =
                (100_u32..105_u32).collect_tuple().unwrap();

            let input = [
                (transaction_1, vec![(contract_a, vec![key_alpha])]),
                (
                    transaction_2,
                    vec![
                        (contract_a, vec![key_beta]),
                        (contract_b, vec![key_alpha, key_beta]),
                    ],
                ),
                (
                    transaction_3,
                    vec![
                        (contract_a, vec![key_alpha]),
                        (contract_b, vec![key_gamma]),
                        (contract_c, vec![key_delta]),
                    ],
                ),
                (
                    transaction_4,
                    vec![
                        (contract_a, vec![key_beta]),
                        (contract_c, vec![key_epsilon]),
                    ],
                ),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Aβ, Bα, Bβ
            // Transaction 3 modifies contract Aα, Bγ, Cδ
            // Transaction 4 modifies contract Aβ, Cγ

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: 1
            // Transaction 3: 1, 2
            // Transaction 4: 1, 2, 3

            // Expected storage dependencies:
            // Transaction 1: None
            // Transaction 2: None
            // Transaction 3: 1
            // Transaction 4: 2

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2, transaction_1],
                vec![transaction_3, transaction_1, transaction_2],
                vec![transaction_4, transaction_1, transaction_2, transaction_3],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3, transaction_1],
                vec![transaction_4, transaction_2],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // Contract dependencies but not storage keys dependencies
        /// Given: Transaction 1, modifies contract A at key α. 2 modifies contract A at key β.
        /// Then: Result should show that B depends on A in contract dependencies, but not StorageEntry dependencies.
        #[test]
        fn contract_not_keys() {
            let (transaction_1, transaction_2) = (1_u32..3_u32).collect_tuple().unwrap();
            let contract_a = 10_u32;
            let (key_alpha, key_beta) = (100_u32..102_u32).collect_tuple().unwrap();

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (transaction_2, vec![(contract_a, [key_beta])]),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Aβ

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: 1

            // Expected storage dependencies:
            // Transaction 1: None
            // Transaction 2: None

            let transactions = Dummy::transaction_traces(input);
            let expected_contracts = vec![vec![transaction_1], vec![transaction_2, transaction_1]];
            let expected_storage_diffs = vec![vec![transaction_1], vec![transaction_2]];
            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // Contract and Storage Keys dependencies are transative.
        /// Given: Transactions (in order) 1, 2, and 3 modify contract A at key α.
        /// Then: Result should show that 3 depends on 2 and 1. 2 depends on 1. 1 has no dependencies.
        #[test]
        fn same_contract_and_storage_key() {
            let (transaction_1, transaction_2, transaction_3) =
                (1_u32..4_u32).collect_tuple().unwrap();
            let contract_a = 10_u32;
            let key_alpha = 100_u32;

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (transaction_2, vec![(contract_a, [key_alpha])]),
                (transaction_3, vec![(contract_a, [key_alpha])]),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Aα
            // Transaction 3 modifies contract Aα

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: 1
            // Transaction 3: 1, 2

            // Expected storage dependencies:
            // Transaction 1: None
            // Transaction 2: 1
            // Transaction 3: 1, 2

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2, transaction_1],
                vec![transaction_3, transaction_1, transaction_2],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2, transaction_1],
                vec![transaction_3, transaction_1, transaction_2],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }

        // same keys different contract addresses
        /// Given: Transactions where: Transactions (in order) 1, and 2 modify contracts A, and B at key α.
        /// Then: Result should show no dependencies.
        #[test]
        fn same_keys_diff_contract() {
            let (transaction_1, transaction_2, transaction_3) =
                (1_u32..4_u32).collect_tuple().unwrap();
            let (contract_a, contract_b, contract_c) = (10_u32..13_u32).collect_tuple().unwrap();
            let key_alpha = 100_u32;

            let input = [
                (transaction_1, vec![(contract_a, [key_alpha])]),
                (transaction_2, vec![(contract_b, [key_alpha])]),
                (transaction_3, vec![(contract_c, [key_alpha])]),
            ];
            // Transaction 1 modifies contract Aα
            // Transaction 2 modifies contract Bα
            // Transaction 3 modifies contract Cα

            // Expected contract dependencies:
            // Transaction 1: None
            // Transaction 2: 1
            // Transaction 3: 1, 2

            // Expected storage dependencies:
            // Transaction 1: None
            // Transaction 2: 1
            // Transaction 3: 1, 2

            let transactions = Dummy::transaction_traces(input);

            let expected_contracts = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
            ];

            let expected_storage_diffs = vec![
                vec![transaction_1],
                vec![transaction_2],
                vec![transaction_3],
            ];

            test_graph_transactions(transactions, expected_contracts, expected_storage_diffs);
        }
    }

    // some transactions have state_diff == None
    /// Scenario: Errors from transactions with `state_diff` should be ignored.
    /// Given: Transactions where one transaction has `state_diff` that is `None`.
    /// Then: The transaction with `state_diff` None should be ignored.
    #[test]
    fn graph_state_diff_none() {
        let transactions = vec![
            Dummy::transaction_trace(1_u32, [(1_u32, [1_u32])]),
            Dummy::transaction_trace_with_none(2_u32),
            Dummy::transaction_trace(3_u32, [(2_u32, [2_u32])]),
        ];

        let expected_contract_dependencies: Vec<Vec<u32>> =
            vec![vec![1_u32], vec![2_u32], vec![3_u32]];
        let expected_storage_dependencies: Vec<Vec<u32>> =
            vec![vec![1_u32], vec![2_u32], vec![3_u32]];
        test_graph_transactions(
            transactions,
            expected_contract_dependencies,
            expected_storage_dependencies,
        );
    }
}
