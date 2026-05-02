use common::{ConnEvent, ExecEvent, OpenEvent};

use crate::bootstrap::AgentBootstrap;
use crate::config::Config;
use crate::conn_handler;
use crate::exec_handler;
use crate::exit_handler;
use crate::open_handler;
use crate::runtime::RuntimeState;
use crate::users::UserDb;


  fn now_unix_ms() -> u64 {
      use std::time::{SystemTime, UNIX_EPOCH};

      SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_millis() as u64
  }

pub async fn run(
    mut bootstrap: AgentBootstrap,
    config: Config,
    user_db: UserDb,
) {
    let mut state = RuntimeState::new(&config);

    println!("Lavender is watching. Ctrl+C to stop");

    loop {
        tokio::select! {
            // arm 1: process execution events.
            // When exec_fd becomes readable, we drain every queued exec record so
            // we don't leave stale events behind between poll cycles.
            Ok(mut guard) = bootstrap.exec_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                // We will drain all currently available events before waiting again
                while let Some(item) = rb.next() {
                    // The kernel writes ExecEvent bytes into the ring buffer map
                    // We just convert those bytes
                    let event = unsafe { &*(item.as_ptr() as *const ExecEvent) };
                    
                    //using this to test if it was working or not will need to update later!
                    let canonical = crate::transport::exec_to_canonical(
                        event,
                        &config.agent.agent_id,
                        "localhost",
                        now_unix_ms(),
                    );

                    if let Ok(json) = serde_json::to_string(&canonical) {
                        println!("{json}");
                    }

                    // This updates process-tree metadata, feeds exec events into correlator,
                    // and checks shell-spawn and obfuscated-command rules.
                    exec_handler::handle_event(
                        event,
                        &mut state,
                        &user_db,
                        &config,
                    );
                }

                // Tell AsyncFd we handled this readiness notification.
                guard.clear_ready();
            }

            // arm 2: process exit events.
            // Exit events let us evict per-pid state so correlation/scoring does not
            // keep dead-process data around.
            Ok(mut guard) = bootstrap.exit_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    // we will read it as u32 directly
                    let pid = unsafe { *(item.as_ptr() as *const u32)};

                    // Cleanup removes pid from process tree, correlator and scorer.
                    exit_handler::handle_event(pid, &mut state);
                }

                guard.clear_ready();
            }

            // arm 3: file-open events.
            // These feed sensitive-file detection and can also contribute to
            // multi-step correlation chains.
            Ok(mut guard) = bootstrap.open_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    // Kernel payloads are raw bytes, we will reinterpret as OpenEvent.
                    let event = unsafe { &*(item.as_ptr() as *const OpenEvent) };

                    // This checks sensitive-file-read rules and feeds file-open events
                    // into correlator so they can participate in chain alerts.
                    open_handler::handle_event(
                        event,
                        &mut state,
                        &config,
                    );
                }

                guard.clear_ready();
            }

            // arm 4: network connect events.
            // These run network-focused detections and also contribute to chain
            // correlation (for example reverse-shell-like behavior).
            Ok(mut guard) = bootstrap.conn_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    // Kernel payloads are raw bytes we will reinterpret as ConnEvent.
                    let event = unsafe { &*(item.as_ptr() as *const ConnEvent) };

                    // This handles first-time network caller tracking plus shell-network
                    // and suspicious-port checks, and feeds connect events into correlator.
                    conn_handler::handle_event(
                        event,
                        &mut state,
                        &user_db,
                        &config,
                    );
                }

                guard.clear_ready();
            }

            // arm 5
            // Shutdowen with Ctrl + C. Don't remove for now
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
        }
    }
}