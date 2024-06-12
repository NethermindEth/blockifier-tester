use itertools::{EitherOrBoth, Itertools};
use serde::Serialize;
use starknet::core::types::{BlockId, FieldElement, TransactionTraceWithHash};

use crate::block_tracer::TraceBlockReport;

// TODO more distinct naming
#[derive(Serialize)]
pub struct BlockTraceResult {
    block_number: u64,
    comparison: BlockTraceComparison,
}

#[derive(Serialize)]
enum BlockTraceComparison {
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

#[derive(Serialize)]
enum TransactionTraceComparison {
    BaseOnly { transaction_hash: FieldElement },
    Both { transaction_hash: FieldElement },
    Error(String),
    NativeOnly { transaction_hash: FieldElement },
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
        .zip_longest(native_traces.into_iter())
        .map(|traces| match traces {
            EitherOrBoth::Both(base_trace, native_trace) => {
                if base_trace.transaction_hash != native_trace.transaction_hash {
                    return TransactionTraceComparison::Error(format!("Mismatched transaction hashes: base = {}, native = {}", base_trace.transaction_hash, native_trace.transaction_hash))
                }
                TransactionTraceComparison::Both {
                    transaction_hash: base_trace.transaction_hash
                }
            },
            EitherOrBoth::Left(base_trace) => TransactionTraceComparison::BaseOnly {
                transaction_hash: base_trace.transaction_hash,
            },
            EitherOrBoth::Right(native_trace) => TransactionTraceComparison::NativeOnly {
                transaction_hash: native_trace.transaction_hash,
            },
        })
        .collect_vec()
}
