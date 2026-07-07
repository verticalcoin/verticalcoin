
## 2024-05-24 - Unintended Value Copies in Legacy BOOST_FOREACH
**Learning:** Legacy `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` silently makes deep copies of complex map elements if the reference operator `&` is omitted. In multithreaded wallet queries, copying large objects like `CWalletTx` causes significant heap allocation overhead.
**Action:** Proactively replace value-copying `BOOST_FOREACH` loops with C++11 range-based `for (const auto& item : map)` loops to eliminate redundant allocations, updating inner pointers to `const T*` to maintain const-correctness.
