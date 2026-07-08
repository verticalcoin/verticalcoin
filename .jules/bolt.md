## 2024-05-24 - Avoid Deep Copies in BOOST_FOREACH Map Iteration
**Learning:** BOOST_FOREACH with PAIRTYPE makes deep value copies of map elements. In multithreaded code where a lock is held, iterating by reference (`const auto&`) prevents unnecessary heap allocations and speeds up iteration significantly.
**Action:** Replace `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` with `for (const auto& item : map)` and update inner pointer declarations to `const` when iterating over large collections of complex objects like `CWalletTx`.
