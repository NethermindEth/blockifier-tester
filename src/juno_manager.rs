use std::{fmt::Display, fs::OpenOptions, path::Path, process::Stdio, time::Duration};

use tokio::process::{Child, Command};

use anyhow::Context;
use log::{debug, info, warn};
use nix::sys::signal;
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

#[derive(Debug)]
pub enum ManagerError {
    Provider(ProviderError),
    Internal(String),
    IO(std::io::Error),
    /// L1HandlerTransaction is not handled yet
    L1HandlerTransaction,
}

impl From<ProviderError> for ManagerError {
    fn from(value: ProviderError) -> Self {
        Self::Provider(value)
    }
}

impl From<std::io::Error> for ManagerError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::Provider(err) => write!(f, "Manager error: {}", err),
            ManagerError::Internal(err) => write!(f, "Internal error: {}", err),
            ManagerError::IO(err) => write!(f, "IO error: {}", err),
            ManagerError::L1HandlerTransaction => write!(f, "L1HandlerTransaction"),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct Config {
    juno_path: String,
    juno_native_path: String,
    juno_mainnet_database_path: String,
    juno_sepolia_database_path: String,
}
impl Config {
    pub fn from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(path)
            .with_context(|| format!("Reading config path: {path:?}"))?;
        Ok(toml::from_str::<Config>(config_str.as_str())?)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Network {
    Mainnet,
    Sepolia,
}

// impl ToString for Network {
//     fn to_string(&self) -> String {
//         match &self {
//         }
//     }
// }
impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Sepolia => write!(f, "sepolia"),
        }
    }
}

pub struct JunoManager {
    pub branch: JunoBranch,
    pub process: Option<Child>,
    pub rpc_client: JsonRpcClient<HttpTransport>,
    pub network: Network,
    juno_path: String,
    juno_native_path: String,
    juno_database_path: String,
}

impl JunoManager {
    pub async fn new(branch: JunoBranch, config: Config, network: Network) -> Self {
        let database_path = if matches!(network, Network::Mainnet) {
            config.juno_mainnet_database_path
        } else {
            config.juno_sepolia_database_path
        };

        let juno_manager = JunoManager {
            branch,
            process: None,
            rpc_client: Self::create_rpc_client(),
            juno_path: config.juno_path,
            juno_native_path: config.juno_native_path,
            juno_database_path: database_path,
            network,
        };

        juno_manager
    }

    pub fn create_rpc_client() -> JsonRpcClient<HttpTransport> {
        JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://localhost:6060/").unwrap(),
        ))
    }

    pub fn spawn_process_unchecked(&mut self) {
        let juno_out_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!(
                "./{}_juno_out.log",
                self.branch.to_string().to_lowercase()
            ))
            .unwrap();

        let juno_err_file = juno_out_file.try_clone().unwrap();

        let process = match self.branch {
            JunoBranch::Base => Command::new(&self.juno_path)
                .args([
                    "--http",
                    "--db-path",
                    &self.juno_database_path,
                    "--network",
                    &self.network.to_string(),
                ])
                .stdin(Stdio::null())
                .stdout(juno_out_file)
                .stderr(juno_err_file)
                .spawn()
                .expect("Failed to spawn base juno"),
            JunoBranch::Native => Command::new(&self.juno_native_path)
                .args([
                    "--http",
                    "--disable-sync",
                    "--db-path",
                    &self.juno_database_path,
                    "--network",
                    &self.network.to_string(),
                ])
                .stdin(Stdio::null())
                .stdout(juno_out_file)
                .stderr(juno_err_file)
                .spawn()
                .context(format!("path: {}", &self.juno_native_path))
                .expect("Failed to spawn native juno"),
        };
        info!("Spawned {} juno with id {:?}", self.branch, process.id());
        self.process = Some(process);
    }

    pub async fn start_juno(&mut self) -> Result<(), ManagerError> {
        let ping_result = self.rpc_client.block_number().await;

        if let Ok(block_number) = ping_result {
            let juno_type = if self.process.is_some() {
                "internal"
            } else {
                "external"
            };
            debug!(
                "{} Juno (as an {juno_type} process) is already live. Pinged with block {block_number}",
                self.branch
            );
            return Ok(());
        }

        info!("Couldn't contact Juno. Re-spawning...");
        let time_limit_seconds = 30;
        for time in 0..time_limit_seconds * 10 {
            if let Some(process) = self.process.as_mut() {
                let exit_code = process.try_wait();
                match exit_code {
                    Ok(Some(_)) => {
                        debug!(
                            "Spawning new {} Juno process as previous one ended",
                            self.branch
                        );
                        self.spawn_process_unchecked()
                    }
                    Ok(None) => {}
                    Err(err) => return Err(ManagerError::Internal(format!("{err}"))),
                }
            } else {
                debug!(
                    "Spawning fresh {} Juno process as none was present or responding",
                    self.branch
                );
                self.spawn_process_unchecked();
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            match self.rpc_client.block_number().await {
                Ok(block_number) => {
                    info!(
                        "{} Juno is alive after {}ms. Pinged  with block {block_number}",
                        self.branch,
                        time * 100,
                    );
                    return Ok(());
                }
                Err(e) => match e {
                    ProviderError::StarknetError(sn_err) => panic!("Starknet error {sn_err:?}"),
                    ProviderError::RateLimited => panic!("Rate limit"),
                    ProviderError::ArrayLengthMismatch => panic!("Array length mismatch"),
                    ProviderError::Other(other_err) => {
                        debug!(
                            "{} Juno is not contactable, retrying. Error: {}",
                            self.branch, other_err
                        )
                    }
                },
            }
        }
        Err(ManagerError::Internal(format!(
            "Failed to set up Juno in {time_limit_seconds} seconds",
        )))
    }

    pub async fn stop_juno(&mut self) -> Result<(), ManagerError> {
        info!("Killing {} Juno... (by ensure_dead)", self.branch);
        if let Some(process) = self.process.take() {
            terminate_process(process).await
        } else {
            warn!("Attempted to automatically kill and restart Juno following an unstable action but no stored process was found. Either an external juno is being used, or ensure_dead has been run multiple times");
            Ok(())
        }
    }

    pub async fn get_block_transaction_count(
        &mut self,
        block_id: BlockId,
    ) -> Result<u64, ManagerError> {
        self.start_juno().await?;
        Ok(self
            .rpc_client
            .get_block_transaction_count(block_id)
            .await?)
    }

    pub async fn get_block_with_txs(
        &mut self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs, ManagerError> {
        self.start_juno().await?;
        self.rpc_client
            .get_block_with_txs(block_id)
            .await
            .map_err(|e| e.into())
    }
}

/// Terminate a child process
///
/// Try to SIGTERM a process and if it does not respond quickly SIGKILL it.
async fn terminate_process(mut process: Child) -> Result<(), ManagerError> {
    let id = match process.id() {
        Some(id) => {
            debug!("Send SIGTERM to {id}");
            let _ = signal::kill(nix::unistd::Pid::from_raw(id as i32), signal::SIGTERM);
            id
        }
        None => {
            debug!("Juno has already been terminated");
            return Ok(());
        }
    };

    // If Juno does not process the SIGTERM within 10 seconds it is SIGKILL'ed.
    tokio::select! {
        status = process.wait() => match status {
            Ok(status) => { debug!("Juno (PID {id}) exited with {status:?}"); Ok(())},
            Err(err) => { Err(ManagerError::Internal(format!("Failed to kill Juno (PID {id}): {err}")))},
        },
        _time = {tokio::time::sleep(Duration::from_secs(10))} => match process.kill().await {
            Ok(()) => {debug!("Forcibly killed Juno (PID {id})"); Ok(())},
            Err(err) => Err(ManagerError::Internal(format!("Failed to kill Juno by force: {err}"))),
        },
    }
}

impl Drop for JunoManager {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            // The SIGTERM handler relies on JunoManager to issue a SIGKILL on drop.
            // See Note [Terminating Juno]
            match futures::executor::block_on(terminate_process(process)) {
                Err(e) => warn!(
                    "FAILED to kill {} Juno (through mem drop). Be sure to kill it manually before running another: {}", self.branch, e
                ),
                Ok(()) => debug!("{} Juno killed (through mem drop) succesfully", self.branch),
            }
        } else {
            debug!(
                "{} Juno wasn't dropped beacuse it was already killed.",
                self.branch
            );
        }
    }
}
