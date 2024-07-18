use std::{fmt::Display, fs::OpenOptions};

use log::{debug, info, warn};

use crate::block_tracer::TraceBlockReport;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet::core::types::SimulationFlag;
use starknet::{
    core::types::{
        BlockId, BroadcastedDeployAccountTransaction, BroadcastedDeployAccountTransactionV1,
        BroadcastedDeployAccountTransactionV3, BroadcastedInvokeTransaction,
        BroadcastedInvokeTransactionV1, BroadcastedInvokeTransactionV3, BroadcastedTransaction,
        DeployAccountTransaction, ExecuteInvocation, ExecutionResult, FieldElement,
        InvokeTransaction, MaybePendingBlockWithTxs, MaybePendingTransactionReceipt,
        SimulatedTransaction, Transaction, TransactionTrace,
    },
    providers::Provider,
};

use crate::{
    juno_manager::{JunoBranch, JunoManager, ManagerError},
    utils,
};

#[allow(dead_code)]
pub enum SimulationStrategy {
    Binary,
    Optimistic,
    Pessimistic,
}
pub trait TransactionSimulator {
    async fn get_transactions_to_simulate(
        &mut self,
        block: &MaybePendingBlockWithTxs,
    ) -> Result<Vec<TransactionToSimulate>, ManagerError>;
    async fn simulate_block(
        &mut self,
        block_number: u64,
        strategy: SimulationStrategy,
        simulation_flags: &[SimulationFlag],
    ) -> Result<BlockSimulationReport, ManagerError>;
    async fn binary_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError>;
    async fn optimistic_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transaction: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError>;
    async fn pessimistic_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BinarySearchParams {
    block: BlockId,
    known_succesful_results: Vec<SimulatedTransaction>,
    known_failure_length: usize,
    i: usize,
}
impl BinarySearchParams {
    fn new(transactions_len: usize, block_id: BlockId) -> Self {
        BinarySearchParams {
            block: block_id,
            known_succesful_results: vec![],
            known_failure_length: transactions_len + 1,
            i: (transactions_len + 1) / 2,
        }
    }
}

fn block_id_to_string(block_id: BlockId) -> String {
    match block_id {
        BlockId::Number(n) => n.to_string(),
        BlockId::Hash(hash) => utils::felt_to_hex(&hash, true),
        BlockId::Tag(tag) => format!("{tag:?}"),
    }
}

impl TransactionSimulator for JunoManager {
    async fn get_transactions_to_simulate(
        &mut self,
        block: &MaybePendingBlockWithTxs,
    ) -> Result<Vec<TransactionToSimulate>, ManagerError> {
        // Make sure it is usable just at the beginning since the RPC call
        // shouldn't crash the node ever (Native unrelated)
        self.ensure_usable().await?;

        let mut result = vec![];
        let max_transaction = block.transactions().len();
        for (i, transaction) in block.transactions().iter().enumerate() {
            let tx_hash = get_block_transaction_hash(transaction);
            debug!("({}/{max_transaction}) Receipt for {tx_hash}...", i + 1);
            let expected_result = self
                .rpc_client
                .get_transaction_receipt(tx_hash)
                .await?
                .into();

            result.push(TransactionToSimulate {
                tx: block_transaction_to_broadcasted_transaction(transaction)?,
                hash: tx_hash,
                expected_result,
            })
        }
        Ok(result)
    }

    async fn simulate_block(
        &mut self,
        block_number: u64,
        strategy: SimulationStrategy,
        simulation_flags: &[SimulationFlag],
    ) -> Result<BlockSimulationReport, ManagerError> {
        info!("Getting block {block_number} with txns");
        let block = self
            .get_block_with_txs(BlockId::Number(block_number))
            .await?;

        info!("Getting transactions to simulate");
        let transactions = self.get_transactions_to_simulate(&block).await?;
        let simulation_results = match strategy {
            SimulationStrategy::Binary => {
                self.binary_repeat_simulate_until_success(
                    BlockId::Number(block_number - 1),
                    &transactions,
                    simulation_flags,
                )
                .await
            }
            SimulationStrategy::Optimistic => {
                self.optimistic_repeat_simulate_until_success(
                    BlockId::Number(block_number - 1),
                    &transactions,
                    simulation_flags,
                )
                .await
            }
            SimulationStrategy::Pessimistic => {
                self.pessimistic_repeat_simulate_until_success(
                    BlockId::Number(block_number - 1),
                    &transactions,
                    simulation_flags,
                )
                .await
            }
        }?;

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
            report.push(SimulationReport {
                tx_hash: tx.hash,
                simulated_result,
                expected_result: tx.expected_result.clone(),
            });
        }

        Ok(BlockSimulationReport {
            simulated_reports: report,
            simulated_transactions: simulation_results,
            transactions_list: transactions,
        })
    }

    // Try all transactions and count down until they all work
    async fn optimistic_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError> {
        let broadcasted_transactions = transactions.iter().map(|tx| tx.tx.clone()).collect_vec();
        for i in 0..transactions.len() {
            let transactions_to_try = &broadcasted_transactions[0..transactions.len() - i];
            info!("Trying {} transactions", transactions_to_try.len());
            self.ensure_usable().await?;
            let simulation_result = self
                .rpc_client
                .simulate_transactions(block_id, transactions_to_try, simulation_flags)
                .await;

            if simulation_result.is_ok() {
                return Ok(simulation_result?);
            } else {
                self.ensure_dead().await?;
            }
        }
        Ok(vec![])
    }

    // Add one transaction at a time to the set that are tried
    async fn pessimistic_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError> {
        let mut results = vec![];

        let broadcasted_transactions = transactions.iter().map(|tx| tx.tx.clone()).collect_vec();
        for i in 0..transactions.len() {
            let transactions_to_try = &broadcasted_transactions[0..i + 1];
            info!("Trying {} transactions", transactions_to_try.len());
            self.ensure_usable().await?;
            let simulation_result = self
                .rpc_client
                .simulate_transactions(block_id, transactions_to_try, simulation_flags)
                .await;

            if simulation_result.is_ok() {
                results = simulation_result.unwrap();
            } else {
                // Wait for current juno process to die so that a new one can be safely started
                self.ensure_dead().await?;
                return Ok(results);
            }
        }
        Ok(results)
    }

    async fn binary_repeat_simulate_until_success(
        &mut self,
        block_id: BlockId,
        transactions: &[TransactionToSimulate],
        simulation_flags: &[SimulationFlag],
    ) -> Result<Vec<SimulatedTransaction>, ManagerError> {
        info!(
            "Searching for failed transaction in block {} (Using binary search)",
            match block_id {
                BlockId::Number(n) => n.to_string(),
                _ => "<block_id is not a number>".into(),
            }
        );

        let cache_path = std::path::Path::new("cache/bin_search");
        let mut search_params = utils::memoized_call(cache_path, || async {
            debug!("cached path was not read. creating new binarysearchparams");
            Ok(BinarySearchParams::new(transactions.len(), block_id))
        })
        .await
        .unwrap();
        if search_params.block != block_id {
            debug!(
                "Cached search params were for a different block. Cached: {}\tRequested: {}",
                block_id_to_string(search_params.block),
                block_id_to_string(block_id)
            );
            search_params = BinarySearchParams::new(transactions.len(), block_id);
        } else {
            debug!("using either cached params or new params");
        }

        let broadcasted_transactions = transactions.iter().map(|tx| tx.tx.clone()).collect_vec();
        loop {
            let _ = utils::try_write_to_file(cache_path, &search_params)
                .await
                .inspect_err(|write_err| {
                    warn!("write error trying to cache binary search: {write_err:?}")
                });

            info!(
                "Last succesful transactions index: {}. First failed transaction index: {}",
                search_params.known_succesful_results.len(),
                search_params.known_failure_length
            );
            info!("Trying {} transactions", search_params.i);
            let transactions_to_try = &broadcasted_transactions[0..(search_params.i)];
            self.ensure_usable().await?;
            let simulation_result = self
                .rpc_client
                .simulate_transactions(block_id, transactions_to_try, simulation_flags)
                .await;

            info!("Finished trying {} transactions", search_params.i);
            match simulation_result {
                Ok(new_succesful_results) => {
                    debug!(
                        "Succesful simulation up to {} transactions",
                        search_params.i
                    );
                    if search_params.i + 1 >= search_params.known_failure_length {
                        return Ok(new_succesful_results);
                    }
                    search_params.known_succesful_results = new_succesful_results;
                    search_params.i = (search_params.i + search_params.known_failure_length) / 2;
                }
                Err(error) => {
                    debug!(
                        "Error simulating {} transactions: {:?}",
                        search_params.i, error
                    );
                    self.ensure_dead().await?;
                    if search_params.i - 1 <= search_params.known_succesful_results.len() {
                        return Ok(search_params.known_succesful_results);
                    } else {
                        search_params.known_failure_length = search_params.i;
                        search_params.i =
                            (search_params.i + search_params.known_succesful_results.len()) / 2;
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum TransactionResult {
    Success,
    Revert { reason: String },
    Crash,
    Unreached,

    // TEMP
    DeployAccount,
    L1Handler,
    Declare,
}

// To be used when outputting in json format
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

pub fn hex_serialize<S>(val: &FieldElement, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{}", hash_to_hex(val)))
}

fn hash_to_hex(h: &FieldElement) -> String {
    BigUint::from_bytes_be(&h.to_bytes_be()).to_str_radix(16)
}

#[derive(Debug, Serialize)]
pub struct SimulationReport {
    #[serde(serialize_with = "hex_serialize")]
    pub tx_hash: FieldElement,
    expected_result: TransactionResult,
    simulated_result: TransactionResult,
}

pub struct BlockSimulationReport {
    pub simulated_reports: Vec<SimulationReport>,
    pub simulated_transactions: Vec<SimulatedTransaction>,
    pub transactions_list: Vec<TransactionToSimulate>,
}

impl Display for SimulationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n\"Hash\": \"{}\",\n\"Expected result\": \"{}\",\n\"Simulated result\": \"{}\"}}",
            self.tx_hash, self.expected_result, self.simulated_result
        )
    }
}

impl SimulationReport {
    pub fn is_correct(&self) -> bool {
        std::mem::discriminant(&self.expected_result)
            == std::mem::discriminant(&self.simulated_result)
    }
}

pub struct TransactionToSimulate {
    tx: BroadcastedTransaction,
    pub hash: FieldElement,
    expected_result: TransactionResult,
}

fn block_transaction_to_broadcasted_transaction(
    transaction: &Transaction,
) -> Result<BroadcastedTransaction, ManagerError> {
    match transaction {
        Transaction::Invoke(invoke_transaction) => match invoke_transaction {
            InvokeTransaction::V0(_) => Err(ManagerError::InternalError("V0 invoke".to_string())),
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
        Transaction::L1Handler(_) => Err(ManagerError::InternalError("L1Handler".to_string())),
        Transaction::Declare(_declare_transaction) => {
            Err(ManagerError::InternalError("Declare".to_string()))
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
        Transaction::Deploy(_) => Err(ManagerError::InternalError("Deploy".to_string())),
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
