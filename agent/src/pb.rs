// Generated protobuf transport types (from proto/lavender.proto, compiled in build.rs).
// This is the wire format the agent publishes; it replaces the hand-mirrored serde
// transport structs one event type at a time.
include!(concat!(env!("OUT_DIR"), "/lavender.v1.rs"));
