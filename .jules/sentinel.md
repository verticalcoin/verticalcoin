## 2024-05-20 - Memory Leak and Buffer Overflow in GetNotQualifyReason
**Vulnerability:** A memory leak was present due to `CVnodeMan::GetNotQualifyReason` dynamically allocating character buffers (`new char[256]`) without proper freeing in the call site in `src/rpc/rpcvnode.cpp`. Additionally, using `sprintf` and hardcoded buffer sizes (`256`) risks a buffer overflow if the formatted string length exceeds the buffer length. This could potentially cause a Denial of Service.
**Learning:** Returning `char*` that transfers ownership requires explicit `delete[]` at all call sites, which is error-prone. Legacy C-style formatting (`sprintf`) on fixed-size buffers introduces buffer overflow risks.
**Prevention:** Use memory-safe, modern C++ constructs: prefer `std::string` as the return type over `char*` arrays and use safe format wrappers like `strprintf` to mitigate both memory leaks and buffer overflows.
## 2024-05-24 - Insecure Randomness in Proxy Authentication
**Vulnerability:** Used non-cryptographic `insecure_rand()` to generate random proxy credentials (SOCKS5 username/password) in `src/netbase.cpp` for stream isolation.
**Learning:** Using weak PRNGs for network credentials degrades stream isolation security, as an attacker might predict the credentials and correlate traffic.
**Prevention:** Always use cryptographically secure random number generators (CSPRNGs) like `GetRandHash()` when generating any network credentials, even when the proxy server ignores them (as Tor does), since the entropy guarantees isolation.
