## 2024-05-20 - Memory Leak and Buffer Overflow in GetNotQualifyReason
**Vulnerability:** A memory leak was present due to `CVnodeMan::GetNotQualifyReason` dynamically allocating character buffers (`new char[256]`) without proper freeing in the call site in `src/rpc/rpcvnode.cpp`. Additionally, using `sprintf` and hardcoded buffer sizes (`256`) risks a buffer overflow if the formatted string length exceeds the buffer length. This could potentially cause a Denial of Service.
**Learning:** Returning `char*` that transfers ownership requires explicit `delete[]` at all call sites, which is error-prone. Legacy C-style formatting (`sprintf`) on fixed-size buffers introduces buffer overflow risks.
**Prevention:** Use memory-safe, modern C++ constructs: prefer `std::string` as the return type over `char*` arrays and use safe format wrappers like `strprintf` to mitigate both memory leaks and buffer overflows.
## 2024-05-15 - Fix weak RNG for Tor stream isolation credentials
**Vulnerability:** The code used `insecure_rand()` to generate usernames and passwords for Tor SOCKS5 proxy authentication, which is intended for stream isolation.
**Learning:** `insecure_rand()` is a weak PRNG and should not be used for security-critical or privacy-critical purposes. Weak credentials could allow an attacker to predict the stream and deanonymize users.
**Prevention:** Always use a cryptographically secure pseudo-random number generator (CSPRNG) like `GetRandHash()` or `GetRand()` for security and privacy credentials.
