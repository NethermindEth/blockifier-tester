use crate::block_tracer::TraceBlockReport;
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use serde::Serialize;
use starknet::core::types::{
    BlockId, ContractStorageDiffItem, DeclaredClassItem, DeployedContractItem, ExecuteInvocation,
    FieldElement, FunctionInvocation, NonceUpdate, OrderedEvent, OrderedMessage, ReplacedClassItem,
    StateDiff, TransactionTrace, TransactionTraceWithHash,
};

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

#[derive(Serialize)]
enum TransactionTraceComparisonBody {
    Mismatch { base: String, native: String },
    Invoke(InvokeTxTraceComparison),
    DeployAccount,
    L1Handler,
    Declare,
}

#[derive(Serialize)]
struct InvokeTxTraceComparison {
    pub execute_invocation: ExecuteInvocationComparison,
    pub validate_invocation: ValidateInvocationComparison,
    pub fee_transfer_invocation: FeeTransferInvocationComparison,
    pub state_diff: StateDiffComparisonType,
}

type ValidateInvocationComparison = BothOptional<FunctionInvocation, FunctionInvocationComparison>;
type FeeTransferInvocationComparison =
    BothOptional<FunctionInvocation, FunctionInvocationComparison>;
type StateDiffComparisonType = BothOptional<StateDiff, StateDiffComparison>;

#[derive(Serialize)]
pub enum BothOptional<T, D> {
    BaseOnly(T),
    NativeOnly(T),
    Both(D),
    NoneBoth,
}

#[derive(Serialize)]
enum ExecuteInvocationComparison {
    BaseFailed {
        reason: String,
        native: FunctionInvocation,
    },
    BothFailed {
        base_reason: String,
        native_reason: String,
    },
    BothSucceeded(FunctionInvocationComparison),
    NativeFailed {
        reason: String,
        base: FunctionInvocation,
    },
}

#[derive(Serialize)]
struct FunctionInvocationComparison {
    pub events: Vec<EventComparison>,
    pub messages: Vec<MessagesComparison>,
    pub call_result: CallResultComparison,
    pub inner_calls: Vec<InnerCallComparison>,
}

#[derive(Serialize)]
pub struct StateDiffComparison {
    pub storage_diffs: Vec<StorageDiffComparison>,
    pub deprecated_declared_classes: Vec<DeprecatedDeclaredClassComparison>,
    pub declared_classes: Vec<DeclaredClassComparison>,
    pub deployed_contracts: Vec<DeployedContractComparison>,
    pub replaced_classes: Vec<ReplacedClassComparison>,
    pub nonces: Vec<NonceUpdateComparison>,
}

type StorageDiffComparison = CompareResult<ContractStorageDiffItem>;
type DeprecatedDeclaredClassComparison = CompareResult<FieldElement>;
type DeclaredClassComparison = CompareResult<DeclaredClassItem>;
type DeployedContractComparison = CompareResult<DeployedContractItem>;
type ReplacedClassComparison = CompareResult<ReplacedClassItem>;
type NonceUpdateComparison = CompareResult<NonceUpdate>;
type EventComparison = CompareResult<OrderedEvent>;
type MessagesComparison = CompareResult<OrderedMessage>;

#[derive(Serialize)]
pub enum CompareResult<T>
where
    T: PartialEq,
{
    Same,
    Different { base: T, native: T },
    LeftOnly(T),
    RightOnly(T),
}

impl<T> CompareResult<T>
where
    T: PartialEq,
{
    pub fn new(base: T, native: T) -> Self {
        if base == native {
            Self::Same
        } else {
            Self::Different { base, native }
        }
    }

    pub fn new_from_vec(base: Vec<T>, native: Vec<T>) -> Vec<Self> {
        base.into_iter()
            .zip_longest(native)
            .map(|item| match item {
                EitherOrBoth::Both(base, native) => Self::new(base, native),
                EitherOrBoth::Left(base) => Self::LeftOnly(base),
                EitherOrBoth::Right(native) => Self::RightOnly(native),
            })
            .collect()
    }
}

type CallResultComparison = CompareResult<String>;

#[derive(Serialize)]
enum InnerCallComparisonInfo {
    Same,
    Different {
        inner_calls: Vec<InnerCallComparison>,
        base: String,
        native: String,
    },
    BaseOnly,
    NativeOnly,
}

#[derive(Serialize)]
struct InnerCallComparison {
    #[serde(serialize_with = "hex_serialize")]
    contract: FieldElement,
    #[serde(serialize_with = "hex_serialize")]
    selector: FieldElement,
    info: InnerCallComparisonInfo,
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
            TransactionTraceComparisonBody::Invoke(InvokeTxTraceComparison {
                execute_invocation: compare_execute_invocation(
                    &base_trace.execute_invocation,
                    &native_trace.execute_invocation,
                ),
                validate_invocation: compare_validate_invocation(
                    &base_trace.validate_invocation,
                    &native_trace.validate_invocation,
                ),
                fee_transfer_invocation: compare_fee_transfer_invocation(
                    &base_trace.fee_transfer_invocation,
                    &native_trace.fee_transfer_invocation,
                ),
                state_diff: compare_state_diff(&base_trace.state_diff, &native_trace.state_diff),
            })
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

fn compare_execute_invocation(
    base: &ExecuteInvocation,
    native: &ExecuteInvocation,
) -> ExecuteInvocationComparison {
    match (base, native) {
        (ExecuteInvocation::Success(base), ExecuteInvocation::Success(native)) => {
            ExecuteInvocationComparison::BothSucceeded(compare_function_invocation(base, native))
        }
        (ExecuteInvocation::Success(base), ExecuteInvocation::Reverted(native)) => {
            ExecuteInvocationComparison::NativeFailed {
                reason: native.revert_reason.clone(),
                base: base.clone(),
            }
        }
        (ExecuteInvocation::Reverted(base), ExecuteInvocation::Success(native)) => {
            ExecuteInvocationComparison::BaseFailed {
                reason: base.revert_reason.clone(),
                native: native.clone(),
            }
        }
        (ExecuteInvocation::Reverted(base), ExecuteInvocation::Reverted(native)) => {
            ExecuteInvocationComparison::BothFailed {
                base_reason: base.revert_reason.clone(),
                native_reason: native.revert_reason.clone(),
            }
        }
    }
}

fn compare_fee_transfer_invocation(
    base: &Option<FunctionInvocation>,
    native: &Option<FunctionInvocation>,
) -> FeeTransferInvocationComparison {
    match (base, native) {
        (Some(base), Some(native)) => BothOptional::Both(compare_function_invocation(base, native)),
        (Some(base), None) => BothOptional::BaseOnly(base.clone()),
        (None, Some(native)) => BothOptional::NativeOnly(native.clone()),
        (None, None) => BothOptional::NoneBoth,
    }
}

fn compare_state_diff(
    base: &Option<StateDiff>,
    native: &Option<StateDiff>,
) -> StateDiffComparisonType {
    match (base, native) {
        (Some(base), Some(native)) => BothOptional::Both(StateDiffComparison {
            storage_diffs: CompareResult::new_from_vec(
                base.storage_diffs.clone(),
                native.storage_diffs.clone(),
            ),
            deprecated_declared_classes: CompareResult::new_from_vec(
                base.deprecated_declared_classes.clone(),
                native.deprecated_declared_classes.clone(),
            ),
            declared_classes: CompareResult::new_from_vec(
                base.declared_classes.clone(),
                native.declared_classes.clone(),
            ),
            deployed_contracts: CompareResult::new_from_vec(
                base.deployed_contracts.clone(),
                native.deployed_contracts.clone(),
            ),
            replaced_classes: CompareResult::new_from_vec(
                base.replaced_classes.clone(),
                native.replaced_classes.clone(),
            ),
            nonces: CompareResult::new_from_vec(base.nonces.clone(), native.nonces.clone()),
        }),
        (Some(base), None) => BothOptional::BaseOnly(base.clone()),
        (None, Some(native)) => BothOptional::NativeOnly(native.clone()),
        (None, None) => BothOptional::NoneBoth,
    }
}

fn compare_function_invocation(
    base: &FunctionInvocation,
    native: &FunctionInvocation,
) -> FunctionInvocationComparison {
    FunctionInvocationComparison {
        events: compare_events(&base.events, &native.events),
        messages: compare_messages(&base.messages, &native.messages),
        call_result: compare_results(&base.result, &native.result),
        inner_calls: compare_inner_calls(&base.calls, &native.calls),
    }
}

fn compare_validate_invocation(
    base: &Option<FunctionInvocation>,
    native: &Option<FunctionInvocation>,
) -> ValidateInvocationComparison {
    match (base, native) {
        (Some(base), Some(native)) => BothOptional::Both(compare_function_invocation(base, native)),
        (Some(base), None) => BothOptional::BaseOnly(base.clone()),
        (None, Some(native)) => BothOptional::NativeOnly(native.clone()),
        (None, None) => BothOptional::NoneBoth,
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

fn compare_messages(
    base_messages: &[OrderedMessage],
    native_messages: &[OrderedMessage],
) -> Vec<MessagesComparison> {
    let mut result = Vec::new();
    for (base_message, native_message) in base_messages.iter().zip(native_messages.iter()) {
        result.push(if base_message == native_message {
            MessagesComparison::Same
        } else {
            MessagesComparison::Different {
                base: base_message.clone(),
                native: native_message.clone(),
            }
        })
    }
    result
}

fn compare_events(
    base_event: &[OrderedEvent],
    native_event: &[OrderedEvent],
) -> Vec<EventComparison> {
    let mut result = Vec::new();
    for (base_event, native_event) in base_event.iter().zip(native_event.iter()) {
        result.push(if base_event == native_event {
            EventComparison::Same
        } else {
            EventComparison::Different {
                base: base_event.clone(),
                native: native_event.clone(),
            }
        })
    }
    result
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
