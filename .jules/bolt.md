## 2025-01-28 - Return large collections by const reference
**Learning:** Returning large collections (like `std::vector<CVnode>`) by value from getter functions (e.g., `GetFullVnodeVector()`) causes expensive deep copies, becoming a significant performance bottleneck.
**Action:** Always return large collections by `const reference` (e.g., `const std::vector<T>&`) in getters and ensure iteration loops use `const reference` (`BOOST_FOREACH(const T&, vec)`) to prevent unnecessary copying and avoid deep copies.
