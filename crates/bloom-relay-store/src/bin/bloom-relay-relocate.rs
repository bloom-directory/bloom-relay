use bloom_relay_store::Store;
use std::{env, path::PathBuf};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = env::args().skip(1);
    let installation_id: Uuid = args.next().ok_or("missing installation UUID")?.parse()?;
    let operation_id: Uuid = args.next().ok_or("missing operation UUID")?.parse()?;
    let placement = args.next().ok_or("missing target placement")?;
    if args.next().is_some() {
        return Err(
            "usage: bloom-relay-relocate INSTALLATION_UUID OPERATION_UUID PLACEMENT".into(),
        );
    }
    let witness = PathBuf::from(env::var("BLOOM_RELAY_RESTORE_WITNESS_PATH")?);
    let store =
        Store::connect_with_witness(&env::var("BLOOM_RELAY_DATABASE_URL")?, witness).await?;
    store
        .relocate(installation_id, operation_id, &placement)
        .await?;
    println!("installation {installation_id} moved to {placement}; DNS reconciliation queued");
    Ok(())
}
