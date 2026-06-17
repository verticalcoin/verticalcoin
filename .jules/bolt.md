## 2024-05-14 - Network message processing optimization
**Learning:** Found an unintentional performance bottleneck in `src/main.cpp` where unhandled network messages use `BOOST_FOREACH(const std::string msg, allMessages)` to search a vector. This causes O(N) heap allocations (string copies) on every unhandled message received.
**Action:** Always replace `BOOST_FOREACH` or range-based for loops that make value copies of complex types (like `std::string`) with `<algorithm>` functions (like `std::find`) or `const auto&` on hot network paths.
