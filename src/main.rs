mod juno_manager;
mod simulate_transaction;
mod trace_block;
mod trace_transaction;

use simulate_transaction::simulate_main;
use trace_block::block_main;
use trace_transaction::transaction_hash_main;

#[tokio::main]
async fn main() {
    transaction_hash_main().await.unwrap();
    block_main().await.unwrap();
    simulate_main().await.unwrap();
}
