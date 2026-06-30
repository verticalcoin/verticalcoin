## 2024-05-20 - Memory Leak and Buffer Overflow in GetNotQualifyReason
**Vulnerability:** A memory leak was present due to `CVnodeMan::GetNotQualifyReason` dynamically allocating character buffers (`new char[256]`) without proper freeing in the call site in `src/rpc/rpcvnode.cpp`. Additionally, using `sprintf` and hardcoded buffer sizes (`256`) risks a buffer overflow if the formatted string length exceeds the buffer length. This could potentially cause a Denial of Service.
**Learning:** Returning `char*` that transfers ownership requires explicit `delete[]` at all call sites, which is error-prone. Legacy C-style formatting (`sprintf`) on fixed-size buffers introduces buffer overflow risks.
**Prevention:** Use memory-safe, modern C++ constructs: prefer `std::string` as the return type over `char*` arrays and use safe format wrappers like `strprintf` to mitigate both memory leaks and buffer overflows.

## 2024-05-21 - Weak PRNG for Proxy Credentials
**Vulnerability:** The proxy connection code used `insecure_rand()` (a weak PRNG) to generate SOCKS5 proxy credentials for circuit isolation.
**Learning:** `insecure_rand()` should never be used for security-critical operations, such as network isolation, as predictable credentials can lead to identity correlation or isolation bypass.
**Prevention:** Always use a CSPRNG, such as `GetRandHash()` or `GetRand()`, for generating credentials or any security-sensitive random values.
