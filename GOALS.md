# Feature Goals
Some features I will implement later:
- Beaconing patterns with regular 30 second callbacks
    Here we track connection timestamps per process and look for regularity
- TLS fingerprinting - JA3/JA4  
     JA3 fingerprinting works by capturing the TLS ClientHello packet and hashing specific fields like cipher suites, extensions, elliptic curves into a fingerprint. Different tools have different fingerprints even on port 443. A Go binary's TLS handshake looks different from Chrome's. This requires either XDP (capturing raw packets before the kernel processes them) or hooking into the TLS stack directly.