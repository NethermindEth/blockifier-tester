// Contains functions for adding transaction and storage dependencies.

use itertools::Itertools;
use serde::Serialize;
use starknet::core::types::{FieldElement, TransactionTraceWithHash};

use crate::{
    graph::{self, DependencyMap},
    transaction_simulator::BlockSimulationReport,
};

pub fn add_report_dependencies<T>(
    transaction: &T,
    transaction_hash: FieldElement,
    dependencies: &Option<(DependencyMap, DependencyMap)>,
) -> serde_json::Value
where
    T: Serialize,
{
    let mut obj = serde_json::value::to_value(transaction).unwrap();
    if let serde_json::Value::Object(ref mut map) = obj {
        let not_found = serde_json::to_value("Not found").unwrap();
        let values = if let Some((contracts, storage)) = dependencies {
            (
                contracts
                    .get(&transaction_hash)
                    .map_or(not_found.clone(), |val| {
                        serde_json::to_value(val).expect("Error converting value to JSON")
                    }),
                storage
                    .get(&transaction_hash)
                    .map_or(not_found.clone(), |val| {
                        serde_json::to_value(val).expect("Error converting value to JSON")
                    }),
            )
        } else {
            (
                serde_json::to_value("Unknown").unwrap(),
                serde_json::to_value("Unknown").unwrap(),
            )
        };
        map.insert("contract_dependencies".to_string(), values.0);
        map.insert("storage_dependencies".to_string(), values.1);
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
    dependencies: Option<(DependencyMap, DependencyMap)>,
) -> serde_json::Value
where
    I: IntoIterator<Item = (T, FieldElement)>,
    T: Serialize,
{
    let mut values = Vec::<serde_json::Value>::new();
    for (item, hash) in transactions {
        let next_value = add_report_dependencies(&item, hash, &dependencies);
        values.push(next_value);
    }
    serde_json::value::to_value(values).unwrap()
}

pub fn simulation_report_dependencies(report: &BlockSimulationReport) -> serde_json::Value {
    let dependencies = get_simulation_dependencies(report);
    to_json_with_dependencies(
        report
            .simulated_reports
            .iter()
            .map(|report| (report, report.tx_hash)),
        Some(dependencies),
    )
}

pub fn block_report_with_dependencies(traces: &Vec<TransactionTraceWithHash>) -> serde_json::Value {
    let dependencies = graph::get_dependencies(traces.iter());

    to_json_with_dependencies(
        traces.iter().map(|trace| (trace, trace.transaction_hash)),
        Some(dependencies),
    )
}
