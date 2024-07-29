// Contains functions for adding transaction and storage dependencies.

use itertools::Itertools;
use serde::Serialize;
use starknet::core::types::{FieldElement, TransactionTraceWithHash};

use crate::{
    graph::{self, DependencyMap},
    transaction_simulator::BlockSimulationReport,
};

pub fn dependencies_to_json(
    transaction_hash: FieldElement,
    maybe_dependency_map: Option<&DependencyMap>,
) -> serde_json::Value {
    let not_found = serde_json::to_value("Not found").unwrap();
    if let Some(dependency_map) = maybe_dependency_map {
        dependency_map
            .get(&transaction_hash)
            .map_or(not_found.clone(), |val| {
                serde_json::to_value(val).expect("Error converting value to JSON")
            })
    } else {
        serde_json::to_value("Unknown").unwrap()
    }
}

pub fn add_report_dependencies<T>(
    transaction: &T,
    transaction_hash: FieldElement,
    contract_dependencies: Option<&DependencyMap>,
    storage_dependencies: Option<&DependencyMap>,
) -> serde_json::Value
where
    T: Serialize,
{
    let mut obj = serde_json::value::to_value(transaction).unwrap();
    if let serde_json::Value::Object(ref mut map) = obj {
        let contracts_value = dependencies_to_json(transaction_hash, contract_dependencies);
        let storage_value = dependencies_to_json(transaction_hash, storage_dependencies);

        map.insert("contract_dependencies".to_string(), contracts_value);
        map.insert("storage_dependencies".to_string(), storage_value);
    }
    obj
}

fn get_simulation_dependencies(
    simulation_report: &BlockSimulationReport,
) -> (DependencyMap, DependencyMap) {
    let transaction_traces_with_hashes = simulation_report
        .transactions_list
        .iter()
        .zip(simulation_report.simulated_transactions.iter())
        .map(|(to_simulate, simulated)| TransactionTraceWithHash {
            transaction_hash: to_simulate.hash,
            trace_root: simulated.transaction_trace.clone(),
        })
        .collect_vec();
    graph::get_dependencies(transaction_traces_with_hashes.iter())
}

pub fn to_json_with_dependencies<I, T>(
    transactions: I,
    contract_dependencies: Option<&DependencyMap>,
    storage_dependencies: Option<&DependencyMap>,
) -> serde_json::Value
where
    I: IntoIterator<Item = (T, FieldElement)>,
    T: Serialize,
{
    let mut values = Vec::<serde_json::Value>::new();
    for (item, hash) in transactions {
        let next_value =
            add_report_dependencies(&item, hash, contract_dependencies, storage_dependencies);
        values.push(next_value);
    }
    serde_json::value::to_value(values).unwrap()
}

pub fn simulation_report_dependencies(report: &BlockSimulationReport) -> serde_json::Value {
    let (contract_dependencies, storage_dependencies) = get_simulation_dependencies(report);
    to_json_with_dependencies(
        report
            .simulated_reports
            .iter()
            .map(|report| (report, report.tx_hash)),
        Some(&contract_dependencies),
        Some(&storage_dependencies),
    )
}

pub fn block_report_with_dependencies(traces: &[TransactionTraceWithHash]) -> serde_json::Value {
    let (contract_dependencies, storage_dependencies) = graph::get_dependencies(traces.iter());

    to_json_with_dependencies(
        traces.iter().map(|trace| (trace, trace.transaction_hash)),
        Some(&contract_dependencies),
        Some(&storage_dependencies),
    )
}
