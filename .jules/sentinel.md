## 2024-05-20 - Memory Leak and Buffer Overflow in GetNotQualifyReason
**Vulnerability:** A memory leak was present due to `CVnodeMan::GetNotQualifyReason` dynamically allocating character buffers (`new char[256]`) without proper freeing in the call site in `src/rpc/rpcvnode.cpp`. Additionally, using `sprintf` and hardcoded buffer sizes (`256`) risks a buffer overflow if the formatted string length exceeds the buffer length. This could potentially cause a Denial of Service.
**Learning:** Returning `char*` that transfers ownership requires explicit `delete[]` at all call sites, which is error-prone. Legacy C-style formatting (`sprintf`) on fixed-size buffers introduces buffer overflow risks.
**Prevention:** Use memory-safe, modern C++ constructs: prefer `std::string` as the return type over `char*` arrays and use safe format wrappers like `strprintf` to mitigate both memory leaks and buffer overflows.

## 2024-05-24 - Weak SOCKS5 Proxy Credentials leading to broken stream isolation
**Vulnerability:** Using `insecure_rand()` (a weak, non-cryptographic PRNG) to generate Tor SOCKS5 usernames and passwords.
**Learning:** `insecure_rand()` is extremely predictable and was used to supposedly generate randomized credentials per proxy connection. Because it's predictable, attackers could potentially determine the stream credentials, compromising Tor stream isolation.
**Prevention:** Always use cryptographically secure random number generation (CSPRNG) like `GetRandHash()` for generating credentials, passwords, or tokens in privacy and security-critical contexts.
