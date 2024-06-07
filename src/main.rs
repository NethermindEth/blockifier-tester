mod simulate_transaction;


#[tokio::main]
async fn main() {
    simulate_transaction::transaction_hash_main().await.unwrap();
    simulate_transaction::block_main().await.unwrap();
    simulate_transaction::simulate_main().await.unwrap();
}
