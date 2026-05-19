## 2024-05-17 - Insecure Randomness and Divide by Zero in Peer Selection
**Vulnerability:** `CDarkSendRelay::Relay()` used the insecure `rand()` function combined with `rand() % nCount` without checking if `nCount` was 0, leading to a potential divide-by-zero vulnerability. Additionally, if `nCount == 1`, an infinite loop would occur because it required two unique peers.
**Learning:** Hardcoded uses of `rand()` in C++ projects for critical things like node selection can lead to non-uniform distribution and predictable patterns. It can also easily introduce math-related crashes (modulo by zero) and infinite loops in peer negotiation logic.
**Prevention:** Always use secure randomness like `GetRandInt()` instead of `rand()`, and ensure proper boundary checks are present for modulo operations or loop invariants dependent on counts.

## 2024-05-18 - Unsafe String Formatting in GetHex
**Vulnerability:** `base_blob::GetHex` used `sprintf` to format hexadecimal characters into a fixed-size character array (`psz`).
**Learning:** Using `sprintf` is inherently unsafe as it does not check the bounds of the destination buffer, creating a potential buffer overflow vulnerability if data sizes change or logic errors are introduced.
**Prevention:** Always use bounds-checking formatting functions like `snprintf` instead of `sprintf` to ensure the bounds of arrays are respected.
