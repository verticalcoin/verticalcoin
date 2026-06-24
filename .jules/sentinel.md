## 2024-05-24 - Cryptographically Insecure PRNG in SOCKS Stream Isolation
**Vulnerability:** SOCKS proxy stream isolation was compromised by using `insecure_rand()` (a weak, predictable random number generator) for creating randomized connection credentials.
**Learning:** Legacy developers may use non-cryptographic PRNG functions out of habit when implementing isolation mechanisms. If isolation credentials are predictable, an attacker might link purportedly isolated streams, defeating privacy networks (like Tor).
**Prevention:** Always use `GetRandHash()` or `GetRand()` when generating anything related to connection credentials, routing isolation, or session keys, reserving `insecure_rand()` solely for non-critical scheduling or trivial randomized backoffs.
