pub mod exec;
pub mod open;
pub mod conn;
pub mod exit;

pub(crate) fn decode_c_string(bytes: &[u8]) -> String {
	let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
	String::from_utf8_lossy(&bytes[..end]).to_string()
}
