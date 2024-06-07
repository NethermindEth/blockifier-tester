use std::{
    process::{self, Command, Stdio},
    time::Duration,
};

use starknet::{
    core::types::{BlockId, MaybePendingBlockWithTxs},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError, Url},
};

pub struct JunoManager {
    pub(crate) process: process::Child,
    pub(crate) rpc_client: JsonRpcClient<HttpTransport>,
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

#[derive(Debug)]
pub enum ManagerError {
    ProviderError(ProviderError),
    InternalError(String),
}

impl From<ProviderError> for ManagerError {
    fn from(value: ProviderError) -> Self {
        Self::ProviderError(value)
    }
}

impl JunoManager {
    pub async fn new() -> Result<Self, ManagerError> {
        let mut juno_manager = JunoManager {
            process: Self::spawn_process_unchecked(),
            rpc_client: Self::create_rpc_client(),
        };

        juno_manager.ensure_usable().await?;
        Ok(juno_manager)
    }

    pub fn spawn_process_unchecked() -> process::Child {
        let process = Command::new("./spawn_native_juno.sh")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Juno spawn script failed");
        println!("Spawned juno with id {}", process.id());
        process
    }

    pub fn create_rpc_client() -> JsonRpcClient<HttpTransport> {
        JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://localhost:6060/").unwrap(),
        ))
    }

    pub async fn ensure_usable(&mut self) -> Result<(), ManagerError> {
        let time_limit_seconds = 30;
        for _ in 0..time_limit_seconds * 10 {
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
                    return Err(ManagerError::InternalError(format!(
                        "error checking whether juno is still running: {e}"
                    )));
                }
            }
        }
        Err(ManagerError::InternalError(
            "Failed to set up juno in 30 seconds".to_string(),
        ))
    }

    pub async fn get_block_with_txs(
        &self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs, ProviderError> {
        self.rpc_client.get_block_with_txs(block_id).await
    }

    pub async fn is_running(&mut self) -> Result<bool, ManagerError> {
        match self.process.try_wait() {
            Ok(Some(_exit_status)) => Ok(false),
            Ok(None) => Ok(true),
            Err(err) => Err(ManagerError::InternalError(format!(
                "Failed to get is_running status for juno: '{}'",
                err
            ))),
        }
    }
}
