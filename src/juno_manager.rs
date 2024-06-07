use std::{
    fmt::Display,
    process::{self, Command, Stdio},
    time::Duration,
};

use starknet::{
    core::types::{BlockId, MaybePendingBlockWithTxs},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError, Url},
};

#[derive(Clone, Copy, Debug)]
#[repr(i8)]
pub enum JunoBranch {
    Base,
    Native,
}

impl Display for JunoBranch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                JunoBranch::Base => "Base",
                JunoBranch::Native => "Native",
            }
        )
    }
}

pub struct JunoManager {
    pub branch: JunoBranch,
    pub process: Option<process::Child>,
    pub rpc_client: JsonRpcClient<HttpTransport>,
}

impl Drop for JunoManager {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            match process.kill() {
                Err(e) => println!(
                    "Failed to kill juno. You will have to kill it manually to run another one. {e}"
                ),
                Ok(_) => println!("Successfully killed juno."),
            }
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
    pub async fn new(branch: JunoBranch) -> Result<Self, ManagerError> {
        let mut juno_manager = JunoManager {
            branch,
            process: None,
            rpc_client: Self::create_rpc_client(),
        };

        juno_manager.ensure_usable().await?;
        if juno_manager.process.is_none() {
            println!("JunoManager::new found existing juno instance");
        }
        Ok(juno_manager)
    }

    pub fn create_rpc_client() -> JsonRpcClient<HttpTransport> {
        JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://localhost:6060/").unwrap(),
        ))
    }

    pub fn spawn_process_unchecked(&mut self) {
        let script_name = match self.branch {
            JunoBranch::Base => "./spawn_base_juno.sh",
            JunoBranch::Native => "./spawn_native_juno.sh",
        };
        let process = Command::new(script_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Juno spawn script failed");
        println!("Spawned {} juno with id {}", self.branch, process.id());
        self.process = Some(process);
    }

    pub async fn ensure_usable(&mut self) -> Result<(), ManagerError> {
        let ping_result = self.rpc_client.block_number().await;

        if let Ok(block_number) = ping_result {
            let juno_type = if self.process.is_some() {
                "Internal"
            } else {
                "External"
            };
            println!("{juno_type} juno already contactable with block number: {block_number}");
            return Ok(());
        }

        println!("ensure_usable found no contactable juno");

        if self.process.is_none() {
            self.spawn_process_unchecked();
        }

        let time_limit_seconds = 30;
        print!("Waiting for juno: ");
        for time in 0..time_limit_seconds * 10 {
            async_std::task::sleep(Duration::from_millis(100)).await;
            if time % 10 == 0 {
                print!("{}s ", time / 10);
            }
            let ping_result = self.rpc_client.block_number().await;
            match ping_result {
                Ok(block_number) => {
                    println!(
                        "\nJuno contactable after {}ms with block number: {block_number}",
                        time * 100
                    );
                    return Ok(());
                }
                Err(e) => match e {
                    ProviderError::StarknetError(_) => todo!("Starknet error"),
                    ProviderError::RateLimited => todo!("Rate limit"),
                    ProviderError::ArrayLengthMismatch => todo!("Array length mismatch"),
                    ProviderError::Other(_) => continue,
                },
            }
        }
        // We were using print! to write the time to a single line, so an empty println makes sure that
        // whatever is printed next has its own line
        println!("");
        Err(ManagerError::InternalError(format!(
            "Failed to set up juno in {time_limit_seconds} seconds",
        )))
    }

    pub async fn get_block_with_txs(
        &mut self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs, ManagerError> {
        self.ensure_usable().await?;
        self.rpc_client.get_block_with_txs(block_id).await.map_err(|e| e.into())
    }

    // TODO replace
    pub async fn is_running(&mut self) -> Result<bool, ManagerError> {
        match self.process.as_mut().unwrap().try_wait() {
            Ok(Some(_exit_status)) => Ok(false),
            Ok(None) => Ok(true),
            Err(err) => Err(ManagerError::InternalError(format!(
                "Failed to get is_running status for juno: '{}'",
                err
            ))),
        }
    }
}
