use bloom_relay_store::Store;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = env::var("BLOOM_RELAY_DATABASE_URL")?;
    let witness = env::var("BLOOM_RELAY_RESTORE_WITNESS_PATH")?;
    Store::connect_with_witness(&url, witness.into()).await?;
    println!("relay schema and restore witness verified");
    Ok(())
}
