pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
