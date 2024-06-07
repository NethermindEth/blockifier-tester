use std::{
    fmt::Display,
    fs,
    io::Read,
    path::Path,
    process::{self, Command, Stdio},
    time::Duration,
};

use futures::future::join_all;
use itertools::Itertools;
use starknet::{
    core::types::{
        BlockId, BroadcastedDeployAccountTransaction, BroadcastedDeployAccountTransactionV1,
        BroadcastedDeployAccountTransactionV3, BroadcastedInvokeTransaction,
        BroadcastedInvokeTransactionV1, BroadcastedInvokeTransactionV3, BroadcastedTransaction,
        DeployAccountTransaction, ExecuteInvocation, ExecutionResult, FieldElement,
        InvokeTransaction, MaybePendingBlockWithTxs, MaybePendingTransactionReceipt,
        SimulatedTransaction, Transaction, TransactionTrace,
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Provider, ProviderError, Url,
    },
};

#[derive(Debug)]
pub enum SimulationError {
    // TODO rename to be more generic
    ProviderError(ProviderError),
    ToolError(String),
}

impl From<ProviderError> for SimulationError {
    fn from(value: ProviderError) -> Self {
        Self::ProviderError(value)
    }
}

#[derive(Clone, Debug)]
enum TraceResult {
    Success,
    OtherError(String),
    NotFound,
    Crash { error: String },
}

impl From<&ProviderError> for TraceResult {
    fn from(value: &ProviderError) -> Self {
        match value {
            ProviderError::StarknetError(starknet_err) => match starknet_err {
                starknet::core::types::StarknetError::FailedToReceiveTransaction => {
                    Self::OtherError("FailedToReceiveTransaction".to_string())
                }
                starknet::core::types::StarknetError::ContractNotFound => Self::NotFound,
                starknet::core::types::StarknetError::BlockNotFound => Self::NotFound,
                starknet::core::types::StarknetError::ClassHashNotFound => Self::NotFound,
                starknet::core::types::StarknetError::TransactionHashNotFound => Self::NotFound,
                starknet::core::types::StarknetError::UnexpectedError(other) => {
                    Self::OtherError(other.clone())
                }
                _ => Self::OtherError(starknet_err.to_string()),
            },
            ProviderError::RateLimited => {
                Self::OtherError("ProviderError::RateLimited".to_string())
            }
            ProviderError::ArrayLengthMismatch => {
                Self::OtherError("ProviderError::ArrayLengthMismatch".to_string())
            }
            ProviderError::Other(other) => Self::Crash {
                error: other.to_string(),
            },
        }
    }
}

impl Display for TraceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            TraceResult::Success => write!(f, "TraceResult::Success"),
            TraceResult::OtherError(error) => write!(f, "TraceResult::OtherError: '{}'", error),
            TraceResult::NotFound => write!(f, "TraceResult::NotFound"),
            TraceResult::Crash { error } => write!(f, "TraceResult::Crash: '{}'", error),
        }
    }
}

#[derive(Clone, Debug)]
enum TransactionResult {
    Success,
    Revert { reason: String },
    Crash,
    Unreached,

    // TEMP
    DeployAccount,
    L1Handler,
    Declare,
}

// Output in json format
impl Display for TransactionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionResult::Success => write!(f, "Success"),
            TransactionResult::Revert { reason } => write!(f, "Reverted: {}", reason),
            TransactionResult::Crash => write!(f, "Crash"),
            TransactionResult::Unreached => write!(f, "Unreached"),
            TransactionResult::DeployAccount => {
                write!(f, "TODO determine success of deploy account transactions")
            }
            TransactionResult::L1Handler => write!(f, "L1Handler transactions not handled yet"),
            TransactionResult::Declare => write!(f, "Declare transactions not handled yet"),
        }
    }
}

impl From<MaybePendingTransactionReceipt> for TransactionResult {
    fn from(value: MaybePendingTransactionReceipt) -> Self {
        match value.execution_result() {
            ExecutionResult::Succeeded => Self::Success,
            ExecutionResult::Reverted { reason } => Self::Revert {
                reason: reason.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub struct SimluationReport {
    tx_hash: FieldElement,
    expected_result: TransactionResult,
    simulated_result: TransactionResult,
}

impl Display for SimluationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n\"Hash\": \"{}\",\n\"Expected result\": \"{}\",\n\"Simulated result\": \"{}\"}}",
            self.tx_hash, self.expected_result, self.simulated_result
        )
    }
}

fn log_block_report(block_number: u64, report: Vec<SimluationReport>) {
    println!("Log report for block {block_number}");
    let text = report
        .iter()
        .map(|simulation_report| format!("{}", simulation_report))
        .join(",\n");
    fs::write(
        Path::new(&format!("./results/{}.json", block_number)),
        format!("{{\n\"Block number\": {block_number}\n\"Transactions\": [\n{text}]}}"),
    )
    .expect("Failed to write block report");
}

struct TransactionToSimulate {
    tx: BroadcastedTransaction,
    hash: FieldElement,
    expected_result: TransactionResult,
}

struct JunoManager {
    process: process::Child,
    rpc_client: JsonRpcClient<HttpTransport>,
}

impl Drop for JunoManager {
    fn drop(&mut self) {
        match self.process.kill() {
            Err(e) => println!(
                "Failed to kill juno. You will have to kill it manually to run another one. {e}"
            ),
            Ok(_) => println!("Successfully killed juno."),
        }
    }
}

pub struct TraceTransactionReport {
    transaction: FieldElement, // Hash of transaction.
    post_response: Result<starknet::core::types::TransactionTrace, ProviderError>,
    result: TraceResult,
    juno_did_crash: bool, // TODO return code?
    juno_output: Option<String>,
}

pub struct TraceBlockReport {
    block: BlockId,
    post_response: Result<Vec<starknet::core::types::TransactionTraceWithHash>, ProviderError>,
    result: TransactionResult,
    juno_did_crash: bool,      // TODO return code?
    juno_output: Option<String>,
}

impl JunoManager {
    pub async fn new() -> Result<Self, SimulationError> {
        let mut juno_manager = JunoManager {
            process: Self::spawn_process_unchecked(),
            rpc_client: Self::create_rpc_client(),
        };

        juno_manager.ensure_usable().await?;
        Ok(juno_manager)
    }

    fn spawn_process_unchecked() -> process::Child {
        let process = Command::new("./spawn_native_juno.sh")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Juno spawn script failed");
        println!("Spawned juno with id {}", process.id());
        process
    }

    fn create_rpc_client() -> JsonRpcClient<HttpTransport> {
        JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://localhost:6060/").unwrap(),
        ))
    }

    pub async fn ensure_usable(&mut self) -> Result<(), SimulationError> {
        for _ in 0..300 {
            async_std::task::sleep(Duration::from_millis(100)).await;
            match self.process.try_wait() {
                Ok(None) => {
                    // juno still running
                    let result = self.rpc_client.block_number().await;
                    // TODO branch on error kind
                    // For now if the block number request fails, we assume juno is just not ready yet
                    if let Ok(block_number) = result {
                        println!("Current block number: {block_number}");
                        return Ok(());
                    }
                }
                Ok(Some(status)) => {
                    // juno shut down
                    println!("Juno exited with status {status}. Retrying");
                    self.process = Self::spawn_process_unchecked();
                }
                Err(e) => {
                    return Err(SimulationError::ToolError(format!(
                        "error checking whether juno is still running: {e}"
                    )));
                }
            }
        }
        Err(SimulationError::ToolError(
            "Failed to set up juno in 30 seconds".to_string(),
        ))
    }

    pub async fn get_expected_transaction_result(
        &self,
        tx_hash: FieldElement,
    ) -> Result<TransactionResult, ProviderError> {
        self.rpc_client
            .get_transaction_receipt(tx_hash)
            .await
            .map(|receipt| receipt.into())
    }

    async fn get_transactions_to_simulate(
        &mut self,
        block: &MaybePendingBlockWithTxs,
    ) -> Result<Vec<TransactionToSimulate>, SimulationError> {
        join_all(block.transactions().iter().map(|tx| async {
            let tx_hash = get_block_transaction_hash(tx);
            self.get_expected_transaction_result(tx_hash)
                .await
                .map_err(SimulationError::from)
                .and_then(|expected_result| {
                    Ok(TransactionToSimulate {
                        tx: block_transaction_to_broadcasted_transaction(tx)?,
                        hash: tx_hash,
                        expected_result,
                    })
                })
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, SimulationError>>()
    }

    async fn get_block_with_txs(
        &self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs, ProviderError> {
        self.rpc_client.get_block_with_txs(block_id).await
    }

    async fn simulate_block(
        &mut self,
        block_number: u64,
    ) -> Result<Vec<SimluationReport>, SimulationError> {
        println!("Getting block {block_number} with txns");
        let block = self
            .get_block_with_txs(BlockId::Number(block_number))
            .await?;

        println!("Getting transactions to simulate");
        let transactions = self.get_transactions_to_simulate(&block).await?;
        let simulation_results = self
            .pessimistic_repeat_simulate_until_success(
                BlockId::Number(block_number - 1),
                &transactions,
            )
            .await?;

        let mut found_crash = false;
        let mut report = vec![];
        for i in 0..transactions.len() {
            let tx = &transactions[i];
            let simulated_result = if i < simulation_results.len() {
                get_simulated_transaction_result(&simulation_results[i])
            } else if found_crash {
                TransactionResult::Unreached
            } else {
                found_crash = true;
                TransactionResult::Crash
            };
            report.push(SimluationReport {
                tx_hash: tx.hash,
                simulated_result,
                expected_result: tx.expected_result.clone(),
            });
        }

        Ok(report)
    }

    // Add one transaction at a time to the set that are tried
    pub async fn pessimistic_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
    ) -> Result<Vec<SimulatedTransaction>, SimulationError> {
        let mut results = vec![];

        let broadcasted_transactions = transactions.iter().map(|tx| tx.tx.clone()).collect_vec();
        for i in 0..transactions.len() {
            let transactions_to_try = &broadcasted_transactions[0..i + 1];
            println!("Trying {} tranactions", transactions_to_try.len());
            let simulation_result = self
                .rpc_client
                .simulate_transactions(block_id, transactions_to_try, [])
                .await;

            if simulation_result.is_ok() {
                results = simulation_result.unwrap();
            } else {
                // Wait for current juno process to die so that a new one can be safely started
                self.process.wait().unwrap();
                self.process = Self::spawn_process_unchecked();
                self.ensure_usable().await?;
                return Ok(results);
            }
        }
        Ok(results)
    }

    async fn is_running(&mut self) -> Result<bool, SimulationError> {
        match self.process.try_wait() {
            Ok(Some(_exit_status)) => Ok(false),
            Ok(None) => Ok(true),
            Err(err) => Err(SimulationError::ToolError(format!(
                "Failed to get is_running status for juno: '{}'",
                err
            ))),
        }
    }

    pub async fn trace_transaction(
        &mut self,
        transaction_hash: &str,
    ) -> Result<TraceTransactionReport, SimulationError> {
        self.ensure_usable().await?;
        let transaction = FieldElement::from_hex_be(transaction_hash)
            .map_err(|e| SimulationError::ToolError(format!("{}", e)))?;
        let trace_result = self.rpc_client.trace_transaction(transaction).await;

        // let result_type: TransactionResult;
        let result_type: TraceResult;
        match &trace_result {
            Ok(_) => {
                result_type = TraceResult::Success;
                println!("ok");
            }
            Err(err) => {
                result_type = TraceResult::from(err);
                println!("err: '{:?}' : type: '{}'", err, result_type);
            }
        };

        let expect_juno_crash: bool = matches!(result_type, TraceResult::Crash { error: _ });
        let juno_did_crash = self.is_running().await?;
        let out_lines: Option<String> = if expect_juno_crash {
            println!("Expect juno to crash.");
            // TODO implement timeout
            let out = self
                .process
                .stdout
                .as_mut()
                .expect("failed to get stdout from juno process");
            let mut lines = String::new();
            let _todo = out.read_to_string(&mut lines);
            Some(lines)
        } else {
            None
        };

        Ok(TraceTransactionReport {
            transaction,
            juno_did_crash,
            juno_output: out_lines,
            result: result_type,
            post_response: trace_result,
        })
    }

    pub async fn trace_block(
        &mut self,
        block_num: u64,
    ) -> Result<TraceBlockReport, SimulationError> {
        self.ensure_usable().await?;

        let block_id = BlockId::Number(block_num);
        let trace_result = self.rpc_client.trace_block_transactions(block_id).await;

        let result_type: TransactionResult;
        let expect_juno_crash: bool;
        match &trace_result {
            Ok(_) => {
                expect_juno_crash = false;
                result_type = TransactionResult::Success;
            }
            Err(_err) => {
                result_type = TransactionResult::Crash;
                expect_juno_crash = true;
            }
        };

        let out_lines: Option<String> = if expect_juno_crash {
            println!("Expect juno to crash.");
            // TODO implement timeout
            let out = self
                .process
                .stdout
                .as_mut()
                .expect("failed to get stdout from juno process");
            let mut lines = String::new();
            let _todo = out.read_to_string(&mut lines);
            Some(lines)
        } else {
            None
        };

        let juno_did_crash = self.is_running().await?;

        Ok(TraceBlockReport {
            block: block_id,
            juno_did_crash,
            juno_output: out_lines,
            result: result_type,
            post_response: trace_result,
        })
    }
}

fn block_transaction_to_broadcasted_transaction(
    transaction: &Transaction,
) -> Result<BroadcastedTransaction, SimulationError> {
    match transaction {
        Transaction::Invoke(invoke_transaction) => match invoke_transaction {
            InvokeTransaction::V0(_) => Err(SimulationError::ToolError("V0 invoke".to_string())),
            InvokeTransaction::V1(tx) => Ok(BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                    sender_address: tx.sender_address,
                    calldata: tx.calldata.clone(),
                    max_fee: tx.max_fee,
                    signature: tx.signature.clone(),
                    nonce: tx.nonce,
                    is_query: false,
                }),
            )),
            InvokeTransaction::V3(tx) => Ok(BroadcastedTransaction::Invoke(
                BroadcastedInvokeTransaction::V3(BroadcastedInvokeTransactionV3 {
                    sender_address: tx.sender_address,
                    calldata: tx.calldata.clone(),
                    signature: tx.signature.clone(),
                    nonce: tx.nonce,
                    resource_bounds: tx.resource_bounds.clone(),
                    tip: tx.tip,
                    paymaster_data: tx.paymaster_data.clone(),
                    account_deployment_data: tx.account_deployment_data.clone(),
                    nonce_data_availability_mode: tx.nonce_data_availability_mode,
                    fee_data_availability_mode: tx.fee_data_availability_mode,
                    is_query: false,
                }),
            )),
        },
        Transaction::L1Handler(_) => Err(SimulationError::ToolError("L1Handler".to_string())),
        Transaction::Declare(_declare_transaction) => {
            Err(SimulationError::ToolError("Declare".to_string()))
            // BroadcastedTransaction::Declare(match declare_transaction {
            //     DeclareTransaction::V0(_) => panic!("V0"),
            //     DeclareTransaction::V1(tx) => {
            //         BroadcastedDeclareTransaction::V1(BroadcastedDeclareTransactionV1 {
            //             sender_address: tx.sender_address,
            //             max_fee: tx.max_fee,
            //             signature: tx.signature.clone(),
            //             nonce: tx.nonce,
            //             contract_class: todo!("contract class"), DO NOT USE todo!
            //             is_query: false,
            //         })
            //     }
            //     DeclareTransaction::V2(_tx) => {
            //         todo!("Declare v2")
            //         // BroadcastedDeclareTransaction::V2()
            //     }
            //     DeclareTransaction::V3(_tx) => {
            //         todo!("Declare v3")
            //         // BroadcastedDeclareTransaction::V3()
            //     }
            // })
        }
        Transaction::Deploy(_) => Err(SimulationError::ToolError("Deploy".to_string())),
        Transaction::DeployAccount(tx) => Ok(BroadcastedTransaction::DeployAccount(match tx {
            DeployAccountTransaction::V1(tx) => {
                BroadcastedDeployAccountTransaction::V1(BroadcastedDeployAccountTransactionV1 {
                    max_fee: tx.max_fee,
                    signature: tx.signature.clone(),
                    nonce: tx.nonce,
                    contract_address_salt: tx.contract_address_salt,
                    constructor_calldata: tx.constructor_calldata.clone(),
                    class_hash: tx.class_hash,
                    is_query: false,
                })
            }
            DeployAccountTransaction::V3(tx) => {
                BroadcastedDeployAccountTransaction::V3(BroadcastedDeployAccountTransactionV3 {
                    signature: tx.signature.clone(),
                    nonce: tx.nonce,
                    contract_address_salt: tx.contract_address_salt,
                    constructor_calldata: tx.constructor_calldata.clone(),
                    class_hash: tx.class_hash,
                    resource_bounds: tx.resource_bounds.clone(),
                    tip: tx.tip,
                    paymaster_data: tx.paymaster_data.clone(),
                    nonce_data_availability_mode: tx.nonce_data_availability_mode,
                    fee_data_availability_mode: tx.fee_data_availability_mode,
                    is_query: false,
                })
            }
        })),
    }
}

fn get_block_transaction_hash(transaction: &Transaction) -> FieldElement {
    match transaction {
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(tx) => tx.transaction_hash,
            InvokeTransaction::V1(tx) => tx.transaction_hash,
            InvokeTransaction::V3(tx) => tx.transaction_hash,
        },
        Transaction::L1Handler(tx) => tx.transaction_hash,
        Transaction::Declare(tx) => *tx.transaction_hash(),
        Transaction::Deploy(tx) => tx.transaction_hash,
        Transaction::DeployAccount(tx) => match tx {
            DeployAccountTransaction::V1(tx) => tx.transaction_hash,
            DeployAccountTransaction::V3(tx) => tx.transaction_hash,
        },
    }
}

// // Try all transactions and count down until they all work
// async fn optimistic_repeat_simulate_until_success(
//     block_id: BlockId,
//     transactions: &[TransactionToSimulate],
// ) -> Vec<SimulatedTransaction> {
//     let broadcasted_transactions = transactions
//         .into_iter()
//         .map(|tx| tx.tx.clone())
//         .collect_vec();
//     for i in 0..transactions.len() {
//         let (juno_process, juno_rpc) = spawn_juno_checked().await;

//         let transactions_to_try = &broadcasted_transactions[0..transactions.len() - i];
//         println!("Trying {} tranactions", transactions_to_try.len());
//         let simulation_result = juno_rpc
//             .simulate_transactions(block_id, transactions_to_try, [])
//             .await;

//         if simulation_result.is_ok() {
//             kill_juno(juno_process);
//             return simulation_result.unwrap();
//         } else {
//             confirm_juno_killed(juno_process);
//         }
//     }
//     vec![]
// }

fn get_simulated_transaction_result(transaction: &SimulatedTransaction) -> TransactionResult {
    match &transaction.transaction_trace {
        TransactionTrace::Invoke(inv) => match &inv.execute_invocation {
            ExecuteInvocation::Success(_) => TransactionResult::Success,
            ExecuteInvocation::Reverted(tx) => TransactionResult::Revert {
                reason: tx.revert_reason.clone(),
            },
        },
        TransactionTrace::DeployAccount(_) => TransactionResult::DeployAccount,
        TransactionTrace::L1Handler(_) => TransactionResult::L1Handler,
        TransactionTrace::Declare(_) => TransactionResult::Declare,
    }
}

pub async fn simulate_main() -> Result<(), SimulationError> {
    let block_number = 610026;
    let mut juno_manager = JunoManager::new().await?;
    let block_report = juno_manager.simulate_block(block_number).await?;
    log_block_report(block_number, block_report);
    println!("//Done {block_number}");

    for block_number in 645000..645100 {
        let block_report = juno_manager.simulate_block(block_number).await?;
        log_block_report(block_number, block_report);
        println!("//Done {block_number}");
    }
    Ok(())
}

pub async fn transaction_hash_main() -> Result<(), SimulationError> {
    // let hash = "0x6faeed8967da5d3c0853b8cf4b40b55661a0f949678d5509254b643d133b769"; // DNE
    let hash = "0x07e3ace3b1c3f76b83b734b7a2ea990fb2823e931fb2ecef5d2677887aed9082"; // Crashes on native
    let mut juno_manager = JunoManager::new().await?;
    let trace_report = juno_manager.trace_transaction(hash).await?;
    println!("transaction: {:?}", trace_report.transaction);
    println!("juno: {:?}", trace_report.juno_output);
    println!("juno crashed? {}", trace_report.juno_did_crash);
    println!("result: {}", trace_report.result);
    match trace_report.post_response {
        Ok(item) => {
            println!("item: {:?}", item);
        }
        Err(err) => {
            println!("error: {}", err);
        }
    };

    println!("//Done {hash}");

    Ok(())
}

pub async fn block_main() -> Result<(), SimulationError> {
    let block_number = 640000;
    let mut juno_manager = JunoManager::new().await?;
    let trace_report = juno_manager.trace_block(block_number).await?;
    println!("block_id: {:?}", trace_report.block);
    println!("juno: {:?}", trace_report.juno_output);
    println!("juno crashed? {}", trace_report.juno_did_crash);
    println!("result: {}", trace_report.result);
    match trace_report.post_response {
        Ok(items) => {
            for item in items {
                println!("item: {:?}", item);
            }
        }
        Err(err) => {
            println!("provider error: {}", err);
        }
    };

    println!("//Done {block_number}");

    Ok(())
}
