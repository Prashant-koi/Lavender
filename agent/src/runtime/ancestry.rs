use std::collections::HashMap;

use super::ProcessNode;

pub fn build_ancestry_chain(pid: u32, tree: &HashMap<u32, ProcessNode>) -> String {
    let mut chain = vec![];
    let mut current_pid = pid;

    //we will walk upward through parents and go max of 8 levels
    // max limit to stop inf loops in case the data is weird
    for _ in 0..8 {
        match tree.get(&current_pid) {
            Some(node) => {
                chain.push(node.comm.clone());
                if node.ppid == 0 || node.ppid == current_pid {
                    //either we reached init or a cycle
                    break;
                }
                current_pid = node.ppid;
            }
            None => break,
        }
    }

    // reverse the chian since we built it button up
    chain.reverse();
    chain.join("=>")
}

pub fn parent_comm_for_pid(pid: u32, tree: &HashMap<u32, ProcessNode>) -> Option<String> {
    let node = tree.get(&pid)?;
    let parent = tree.get(&node.ppid)?;
    Some(parent.comm.clone())
}

pub fn ancestry_or_unknown(ancestry: String) -> String {
    if ancestry.is_empty() {
        "unknown".to_string()
    } else {
        ancestry
    }
}
