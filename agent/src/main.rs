use agent::bootstrap;
use agent::config;
use agent::event_loop;
use agent::publisher::Publisher;
use agent::users;

#[tokio::main]
async fn main() {
    // we will load the config first
    let config = config::Config::load_auto();
    let user_db = users::UserDb::load();

    // The publisher owns the outbound NATS connection used for raw telemetry transport.
    let publisher = Publisher::connect(
        &config.agent.nats_url,
        &config.agent.telemetry_subject_prefix,
        &config.agent.tenant_id,
    )
    .await
    .expect("failed to connect to NATS");

    let bootstrap = bootstrap::bootstrap_bpf();
    event_loop::run(bootstrap, config, user_db, publisher).await;
}
