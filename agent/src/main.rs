use agent::bootstrap;
use agent::config;
use agent::event_loop;
use agent::users;

#[tokio::main]
async fn main() {
    // we will load the config first
    let config = config::Config::load_auto();
    let user_db = users::UserDb::load();

    let bootstrap = bootstrap::bootstrap_bpf();
    event_loop::run(bootstrap, config, user_db).await;
}