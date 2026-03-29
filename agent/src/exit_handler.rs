use std::collections::HashMap;

use crate::correlator::Correlator;
use crate::runtime::ProcessNode;
use crate::scorer::Scorer;

pub fn handle_event(
    pid: u32,
    process_tree: &mut HashMap<u32, ProcessNode>,
    correlator: &mut Correlator,
    scorer: &mut Scorer,
) {
    //remove from tree
    if process_tree.remove(&pid).is_some() {
        // uncomment while testing, NOTE TO SELF
        // println!("[exit     {:>6}] removed from tree", pid)
    }

    correlator.remove(pid); //remove from correlator map

    scorer.remove(pid);

    // temporary debug line
    // println!("[tree size: {}]", process_tree.len());
}
