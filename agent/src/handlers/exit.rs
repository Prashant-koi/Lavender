use crate::runtime::RuntimeState;

/// Handles one process-exit event.
///
/// Removes pid-scoped runtime state so process tree, correlator buffers,
/// and scoring data do not retain entries for exited processes.
pub fn handle_event(
    pid: u32,
    state: &mut RuntimeState,
) {
    //remove from tree
    if state.process_tree.remove(&pid).is_some() {
        // uncomment while testing, NOTE TO SELF
        // println!("[exit     {:>6}] removed from tree", pid)
    }

    state.correlator.remove(pid); //remove from correlator map

    state.scorer.remove(pid);

    // temporary debug line
    // println!("[tree size: {}]", process_tree.len());
}
