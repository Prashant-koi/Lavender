use crate::runtime::RuntimeState;

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
