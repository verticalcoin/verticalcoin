## 2024-05-18 - Insecure Randomness in SOCKS5 Proxy Credentials
**Vulnerability:** SOCKS5 proxy credentials were built using `insecure_rand()` which uses a weak PRNG (George Marsaglia's MWC).
**Learning:** `insecure_rand()` should never be used for security context like network credentials, because it lacks cryptographic strength. It makes proxy authentication streams predictable, breaking stream isolation meant to provide network-level privacy and allowing attackers to correlate and de-anonymize transactions.
**Prevention:** Always use cryptographically secure random number generators (`GetRandHash()`, `GetRand()`) for generating secure tokens, salts, or credentials in any network or consensus protocol code.
