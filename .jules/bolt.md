## 2023-10-27 - Eliminating BOOST_FOREACH Map Value Copies
**Learning:** `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` iterates by value, causing hidden, expensive deep copies of the pair (including its values, like the heavy `CWalletTx` object) on every loop iteration.
**Action:** Always replace legacy `BOOST_FOREACH` macros that iterate over maps with modern C++11 range-based `for` loops (e.g., `for (auto& item : map)`) to utilize references and completely eliminate unnecessary heap allocations and deep copies.
