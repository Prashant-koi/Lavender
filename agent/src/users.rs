use std::{collections::HashMap};

pub struct UserDb {
    map: HashMap<u32, String>,
}

//implement some methods for the struct UserDb
impl UserDb {
    pub fn load() -> Self {
        let mut map = HashMap::new();

        // we will read /etc/passwd if it fails we will return empty db
        // the agent will still work it just will show uid numbers instead of names
        let contents = match std::fs::read_to_string("/etc/passwd") {
            Ok(c) => c,
            Err(_) => return Self { map },
            
        };

        for line in contents.lines() {
            // skip comment
            if line.starts_with("#") {continue;}

            let fields: Vec<&str> = line.split(":").collect();

            // since passwd has 7fields we will skip malformed lines
            if fields.len() < 3 {continue;}

            let username = fields[0].to_string();
            let uid: u32 = match fields[2].parse() {
                Ok(u) => u,
                Err(_) => continue,
            };

            map.insert(uid, username);
        }
        Self { map }
    }

    pub fn resolve(&self, uid: u32) -> String {
        match self.map.get(&uid) {
            Some(name) => name.clone(),
            // since uid is not in passwd we wil fallback to using number
            // this might happen for container uid or similar stuff like unusual system accounts etc
            None => format!("uid:{}", uid),
        }
    }
}
