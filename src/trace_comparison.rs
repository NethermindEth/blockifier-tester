use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet::core::types::{
    BlockId, ExecuteInvocation, FieldElement, FunctionInvocation, TransactionTrace,
    TransactionTraceWithHash,
};
// use super::{serde_impls::NumAsHex, *};
// use starknet::core::types::serde_impls;

use crate::block_tracer::TraceBlockReport;

// TODO more distinct naming
#[derive(Serialize, Deserialize)]
pub struct BlockTraceResult {
    pub block_number: u64,
    pub comparison: BlockTraceComparison,
}

#[derive(Serialize, Deserialize)]
pub enum BlockTraceComparison {
    BothSucceeded {
        transaction_traces: Vec<TransactionTraceComparison>,
    },
    BaseFailed(String),
    NativeFailed(String),
    BothFailed {
        base_error: String,
        native_error: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum TransactionTraceComparison {
    BaseOnly {
        transaction_hash: String,
    },
    Both {
        transaction_hash: String,
        body: TransactionTraceComparisonBody,
    },
    Error(String),
    NativeOnly {
        transaction_hash: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum TransactionTraceComparisonBody {
    Mismatch { base: String, native: String },
    Invoke(InvokeComparison),
    DeployAccount,
    L1Handler,
    Declare,
}

#[derive(Serialize, Deserialize)]
pub enum InvokeComparison {
    BaseFailed(String),
    BothFailed {
        base_reason: String,
        native_reason: String,
    },
    BothSucceeded {
        results: CallResultComparison,
        inner_calls: Vec<InnerCallComparison>,
    },
    NativeFailed(Vec<String>),
}

#[derive(Serialize, Deserialize)]
pub enum CallResultComparison {
    Same,
    Different { base: String, native: String },
}

#[derive(Serialize, Deserialize)]
pub enum InnerCallComparisonInfo {
    Same,
    Different {
        inner_calls: Vec<InnerCallComparison>,
        base: String,
        native: String,
    },
    BaseOnly,
    NativeOnly,
}

#[derive(Serialize, Deserialize)]
pub struct InnerCallComparison {
    #[serde(serialize_with = "hex_serialize")]
    pub contract: FieldElement,
    #[serde(serialize_with = "hex_serialize")]
    pub selector: FieldElement,
    pub info: InnerCallComparisonInfo,
}

pub fn hex_serialize<S>(val: &FieldElement, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{}", hash_to_hex(val)))
}

pub fn generate_comparison(
    base_report: TraceBlockReport,
    native_report: TraceBlockReport,
) -> BlockTraceResult {
    let block_number = match (base_report.block, native_report.block) {
        (BlockId::Number(base_block_number), BlockId::Number(native_block_number)) => {
            assert_eq!(
                base_block_number, native_block_number,
                "Attempted to do block comparison for different blocks"
            );
            base_block_number
        }
        _ => todo!("Serializing non-block-number block ids not implemented yet"),
    };
    BlockTraceResult {
        block_number,
        comparison: match (base_report.post_response, native_report.post_response) {
            (Ok(base_traces), Ok(native_traces)) => BlockTraceComparison::BothSucceeded {
                transaction_traces: compare_traces(base_traces, native_traces),
            },
            (Ok(_), Err(native_err)) => BlockTraceComparison::NativeFailed(native_err.to_string()),
            (Err(base_err), Ok(_)) => BlockTraceComparison::BaseFailed(base_err.to_string()),
            (Err(base_err), Err(native_err)) => BlockTraceComparison::BothFailed {
                base_error: base_err.to_string(),
                native_error: native_err.to_string(),
            },
        },
    }
}

fn compare_traces(
    base_traces: Vec<TransactionTraceWithHash>,
    native_traces: Vec<TransactionTraceWithHash>,
) -> Vec<TransactionTraceComparison> {
    base_traces
        .into_iter()
        .zip_longest(native_traces)
        .map(|traces| match traces {
            EitherOrBoth::Both(base_trace, native_trace) => {
                if base_trace.transaction_hash != native_trace.transaction_hash {
                    return TransactionTraceComparison::Error(format!(
                        "Mismatched transaction hashes: base = {}, native = {}",
                        hash_to_hex(&base_trace.transaction_hash),
                        hash_to_hex(&native_trace.transaction_hash)
                    ));
                }
                TransactionTraceComparison::Both {
                    transaction_hash: hash_to_hex(&base_trace.transaction_hash),
                    body: generate_trace_comparison_body(
                        base_trace.trace_root,
                        native_trace.trace_root,
                    ),
                }
            }
            EitherOrBoth::Left(base_trace) => TransactionTraceComparison::BaseOnly {
                transaction_hash: hash_to_hex(&base_trace.transaction_hash),
            },
            EitherOrBoth::Right(native_trace) => TransactionTraceComparison::NativeOnly {
                transaction_hash: hash_to_hex(&native_trace.transaction_hash),
            },
        })
        .collect_vec()
}

fn generate_trace_comparison_body(
    base_trace: TransactionTrace,
    native_trace: TransactionTrace,
) -> TransactionTraceComparisonBody {
    match (&base_trace, &native_trace) {
        (TransactionTrace::Invoke(base_trace), TransactionTrace::Invoke(native_trace)) => {
            TransactionTraceComparisonBody::Invoke(
                match (
                    &base_trace.execute_invocation,
                    &native_trace.execute_invocation,
                ) {
                    (ExecuteInvocation::Success(base), ExecuteInvocation::Success(native)) => {
                        // TODO get which function was called from juno
                        InvokeComparison::BothSucceeded {
                            results: compare_results(&base.result, &native.result),
                            inner_calls: compare_inner_calls(&base.calls, &native.calls),
                        }
                    }
                    (ExecuteInvocation::Success(_), ExecuteInvocation::Reverted(native)) => {
                        InvokeComparison::NativeFailed(
                            native
                                .revert_reason
                                .split('\n')
                                .map(|line| line.to_string())
                                .collect_vec(),
                        )
                    }
                    (ExecuteInvocation::Reverted(base), ExecuteInvocation::Success(_)) => {
                        InvokeComparison::BaseFailed(base.revert_reason.clone())
                    }
                    (ExecuteInvocation::Reverted(base), ExecuteInvocation::Reverted(native)) => {
                        InvokeComparison::BothFailed {
                            base_reason: base.revert_reason.clone(),
                            native_reason: native.revert_reason.clone(),
                        }
                    }
                },
            )
        }
        (TransactionTrace::DeployAccount(_), TransactionTrace::DeployAccount(_)) => {
            TransactionTraceComparisonBody::DeployAccount
        }
        (TransactionTrace::L1Handler(_), TransactionTrace::L1Handler(_)) => {
            TransactionTraceComparisonBody::L1Handler
        }
        (TransactionTrace::Declare(_), TransactionTrace::Declare(_)) => {
            TransactionTraceComparisonBody::Declare
        }
        _ => TransactionTraceComparisonBody::Mismatch {
            base: get_trace_kind(&base_trace),
            native: get_trace_kind(&native_trace),
        },
    }
}

fn compare_inner_calls(
    base_calls: &[FunctionInvocation],
    native_calls: &[FunctionInvocation],
) -> Vec<InnerCallComparison> {
    base_calls
        .iter()
        .zip_longest(native_calls.iter())
        .map(|calls| match calls {
            EitherOrBoth::Both(base_call, native_call) => {
                if base_call.result == native_call.result {
                    // TODO deep check?
                    InnerCallComparison {
                        info: InnerCallComparisonInfo::Same,
                        contract: base_call.contract_address,
                        selector: base_call.entry_point_selector,
                    }
                } else {
                    InnerCallComparison {
                        contract: base_call.contract_address,
                        selector: base_call.entry_point_selector,
                        info: InnerCallComparisonInfo::Different {
                            base: result_felts_to_string(&base_call.result),
                            native: result_felts_to_string(&native_call.result),
                            inner_calls: compare_inner_calls(&base_call.calls, &native_call.calls),
                        },
                    }
                }
            }
            EitherOrBoth::Left(base_call) => InnerCallComparison {
                contract: base_call.contract_address,
                selector: base_call.entry_point_selector,
                info: InnerCallComparisonInfo::BaseOnly,
            },
            EitherOrBoth::Right(native_call) => InnerCallComparison {
                contract: native_call.contract_address,
                selector: native_call.entry_point_selector,
                info: InnerCallComparisonInfo::NativeOnly,
            },
        })
        .collect_vec()
}

fn compare_results(
    base_result: &Vec<FieldElement>,
    native_result: &Vec<FieldElement>,
) -> CallResultComparison {
    if base_result == native_result {
        CallResultComparison::Same
    } else {
        CallResultComparison::Different {
            base: result_felts_to_string(base_result),
            native: result_felts_to_string(native_result),
        }
    }
}

fn get_trace_kind(trace: &TransactionTrace) -> String {
    match trace {
        TransactionTrace::Invoke(_) => "Invoke",
        TransactionTrace::DeployAccount(_) => "DeployAccount",
        TransactionTrace::L1Handler(_) => "L1Handler",
        TransactionTrace::Declare(_) => "Declare",
    }
    .to_string()
}

fn hash_to_hex(h: &FieldElement) -> String {
    BigUint::from_bytes_be(&h.to_bytes_be()).to_str_radix(16)
}

fn result_felts_to_string(results: &[FieldElement]) -> String {
    results.iter().map(|element| element.to_string()).join(", ")
}
