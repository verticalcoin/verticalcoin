## 2024-05-24 - Avoid Deep Copies of Complex Types in Legacy BOOST_FOREACH
**Learning:** Legacy `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` constructs silently make deep copies of the map values (V), which in the case of complex types like `CWalletTx` causes significant heap allocation overhead during iteration.
**Action:** Replace `BOOST_FOREACH` over maps with C++11 range-based for loops using references (e.g., `for (auto& item : map)`) to eliminate redundant heap allocations when iterating over transactions in `CWallet`.
