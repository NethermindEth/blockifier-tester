use std::{
    fmt::Display,
    fs::OpenOptions,
    path::Path,
    process::{self, Command, Stdio},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use log::{debug, info, warn};
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
    ProviderError(ProviderError),
    InternalError(String),
}

impl From<ProviderError> for ManagerError {
    fn from(value: ProviderError) -> Self {
        Self::ProviderError(value)
    }
}

impl Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::ProviderError(err) => write!(f, "Manager error: {}", err),
            ManagerError::InternalError(err) => write!(f, "Internal error: {}", err),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct Config {
    juno_path: String,
    juno_native_path: String,
    juno_database_path: String,
}
impl Config {
    fn from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let config_str = std::fs::read_to_string(path)
            .with_context(|| format!("Reading config path: {path:?}"))?;
        Ok(toml::from_str::<Config>(config_str.as_str())?)
    }
}

pub struct JunoManager {
    pub branch: JunoBranch,
    pub process: Option<process::Child>,
    pub rpc_client: JsonRpcClient<HttpTransport>,
    juno_path: String,
    juno_native_path: String,
    juno_database_path: String,
}

impl JunoManager {
    pub async fn new(branch: JunoBranch) -> Result<Self, ManagerError> {
        let config = Config::from_path(Path::new("./config.toml")).map_err(|e| {
            ManagerError::InternalError(format!("Failed to create config: '{e:?}'"))
        })?;

        let mut juno_manager = JunoManager {
            branch,
            process: None,
            rpc_client: Self::create_rpc_client(),
            juno_path: config.juno_path,
            juno_native_path: config.juno_native_path,
            juno_database_path: config.juno_database_path,
        };

        juno_manager.ensure_usable().await?;
        if juno_manager.process.is_none() {
            warn!("Didn't create a new Juno instance because an existing one was found");
        }
        Ok(juno_manager)
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
                .args(["--http", "--db-path", &self.juno_database_path])
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
                ])
                .stdin(Stdio::null())
                .stdout(juno_out_file)
                .stderr(juno_err_file)
                .spawn()
                .context(format!("path: {}", &self.juno_native_path))
                .expect("Failed to spawn native juno"),
        };
        info!("Spawned {} juno with id {}", self.branch, process.id());
        self.process = Some(process);
    }

    pub async fn ensure_usable(&mut self) -> Result<(), ManagerError> {
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
                    Err(err) => return Err(ManagerError::InternalError(format!("{err}"))),
                }
            } else {
                debug!(
                    "Spawning fresh {} Juno process as none was present or responding",
                    self.branch
                );
                self.spawn_process_unchecked();
            }

            async_std::task::sleep(Duration::from_millis(100)).await;
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
        Err(ManagerError::InternalError(format!(
            "Failed to set up Juno in {time_limit_seconds} seconds",
        )))
    }

    pub async fn ensure_dead(&mut self) -> Result<(), ManagerError> {
        let start_time = SystemTime::now();
        info!("Killing {} Juno... (by ensure_dead)", self.branch);
        if let Some(process) = self.process.as_mut() {
            let id = process.id().to_string();
            debug!("Spawning kill -s INT {id}");
            let mut kill = Command::new("kill")
                .args(["-s", "INT", &id])
                .spawn()
                .expect("Failed to spawn kill process");
            kill.wait().expect("Failed to send sigint");
            self.process = None;
            while start_time.elapsed().unwrap().as_secs() < 30 {
                let ping_result = self.rpc_client.block_number().await;
                match ping_result {
                    Ok(_) => {
                        async_std::task::sleep(Duration::from_millis(100)).await;
                    }
                    Err(err) => {
                        info!("{} Juno Killed", self.branch);
                        debug!("Received error (as expected): {err}");
                        return Ok(());
                    }
                }
            }
            Err(ManagerError::InternalError(
                "Juno still contactable after 30 seconds".to_string(),
            ))
        } else {
            warn!("Attempted to automatically kill and restart Juno following an unstable action but no stored process was found. Either an external juno is being used, or ensure_dead has been run multiple times");
            Ok(())
        }
    }

    pub async fn get_block_transaction_count(
        &mut self,
        block_id: BlockId,
    ) -> Result<u64, ManagerError> {
        self.ensure_usable().await?;
        Ok(self
            .rpc_client
            .get_block_transaction_count(block_id)
            .await?)
    }

    pub async fn get_block_with_txs(
        &mut self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs, ManagerError> {
        self.ensure_usable().await?;
        self.rpc_client
            .get_block_with_txs(block_id)
            .await
            .map_err(|e| e.into())
    }
}

impl Drop for JunoManager {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // The SIGTERM handler relies on JunoManager to issue a SIGKILL on drop.
            // See Note [Terminating Juno]
            match process.kill() {
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
