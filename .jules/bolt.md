## 2024-06-25 - Avoid `BOOST_FOREACH` with `PAIRTYPE`
**Learning:** `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` silently makes deep copies of map elements on every iteration, leading to significant memory allocations and performance degradation, particularly when iterating over large collections like `mapWallet`.
**Action:** Always replace legacy `BOOST_FOREACH(PAIRTYPE...` macro uses with modern C++11 range-based for loops (e.g., `for (const auto& item : map)`) to pass by reference and avoid hidden copies.
