use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    process::{self, Command, Stdio},
    time::{Duration, SystemTime},
};

use starknet::{
    core::types::{BlockId, MaybePendingBlockWithTxs},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, ProviderError, Url},
};

const BASE_JUNO_PATH: &str = "/home/dom/nethermind/nubia/juno/base/build/juno";
const NATIVE_JUNO_PATH: &str = "/home/dom/nethermind/nubia/juno/native/build/juno";
const JUNO_DATABASE_PATH: &str = "/home/dom/nethermind/nubia/juno/database";

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
        // let script_name = match self.branch {
        //     JunoBranch::Base => "./spawn_base_juno.sh",
        //     JunoBranch::Native => "./spawn_native_juno.sh",
        // };
        // let process = Command::new(script_name)
        //     .stdin(Stdio::null())
        //     .stdout(Stdio::piped())
        //     .stderr(Stdio::piped())
        //     .spawn()
        //     .expect("Juno spawn script failed");
        // println!("Spawned {} juno with id {}", self.branch, process.id());
        // self.process = Some(process);
        let juno_out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("./juno_out.txt")
            .unwrap();
        let juno_err_file = juno_out_file.try_clone().unwrap();
        let process = match self.branch {
            JunoBranch::Base => Command::new(BASE_JUNO_PATH)
                .args(["--http", "--db-path", JUNO_DATABASE_PATH])
                .stdin(Stdio::null())
                .stdout(juno_out_file)
                .stderr(juno_err_file)
                .spawn()
                .expect("Failed to spawn base juno"),
            JunoBranch::Native => Command::new(NATIVE_JUNO_PATH)
                .args(["--http", "--disable-sync", "--db-path", JUNO_DATABASE_PATH])
                .stdin(Stdio::null())
                .stdout(juno_out_file)
                .stderr(juno_err_file)
                .spawn()
                .expect("Failed to spawn native juno"),
        };
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

        
        let time_limit_seconds = 30;
        print!("Waiting for juno: ");
        for time in 0..time_limit_seconds * 10 {
            if let Some(process) = self.process.as_mut() {
                let exit_code = process.try_wait();
                match exit_code {
                    Ok(Some(_)) => {
                        println!("Spawning new process as previous one ended");
                        self.spawn_process_unchecked()
                    },
                    Ok(None) => {},
                    Err(err) => return Err(ManagerError::InternalError(format!("{err}"))),
                }
            } else {
                println!("Spawning fresh process as none was present or responding");
                self.spawn_process_unchecked();
            }
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
                    ProviderError::StarknetError(_) => todo!("Starknet error {e:?}"),
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

    pub async fn ensure_dead(&mut self) -> Result<(), ManagerError> {
        let start_time = SystemTime::now();
        println!("Ensuring juno is dead");
        if let Some(process) = self.process.as_mut() {
            let id = process.id().to_string();
            println!("Spawning kill -s INT {id}");
            let mut kill = Command::new("kill")
                .args(["-s", "INT", &id])
                .spawn()
                .expect("Failed to spawn kill process");
            kill.wait().expect("Failed to send sigint");
            self.process = None;
            println!("Sent sigint to child");
        }
        while start_time.elapsed().unwrap().as_secs() < 30 {
            let ping_result = self.rpc_client.block_number().await;
            match ping_result {
                Ok(_) => {
                    async_std::task::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => {
                    println!("Received error (as expected) when killing juno: {err}");
                    return Ok(());
                }
            }
        }
        Err(ManagerError::InternalError(
            "Juno still contactable after 30 seconds".to_string(),
        ))
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
