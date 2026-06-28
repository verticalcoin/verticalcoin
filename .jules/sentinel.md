## 2024-05-20 - Memory Leak and Buffer Overflow in GetNotQualifyReason
**Vulnerability:** A memory leak was present due to `CVnodeMan::GetNotQualifyReason` dynamically allocating character buffers (`new char[256]`) without proper freeing in the call site in `src/rpc/rpcvnode.cpp`. Additionally, using `sprintf` and hardcoded buffer sizes (`256`) risks a buffer overflow if the formatted string length exceeds the buffer length. This could potentially cause a Denial of Service.
**Learning:** Returning `char*` that transfers ownership requires explicit `delete[]` at all call sites, which is error-prone. Legacy C-style formatting (`sprintf`) on fixed-size buffers introduces buffer overflow risks.
**Prevention:** Use memory-safe, modern C++ constructs: prefer `std::string` as the return type over `char*` arrays and use safe format wrappers like `strprintf` to mitigate both memory leaks and buffer overflows.
## 2024-05-24 - Secure PRNG for Proxy Credentials
**Vulnerability:** SOCKS5 proxy credentials were generated using `insecure_rand()`.
**Learning:** `insecure_rand()` is not cryptographically secure and produces predictable outputs. Using it for proxy credentials compromises stream isolation and privacy by allowing network traffic to be tracked.
**Prevention:** Always use a CSPRNG such as `GetRandHash()` or `GetRand()` when generating sensitive data like network credentials, tokens, or encryption keys.
