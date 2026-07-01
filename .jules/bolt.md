## 2024-05-18 - Avoid deep copies in map iteration
**Learning:** Legacy Boost loops like `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` perform silent deep copies.
**Action:** Replace `BOOST_FOREACH(PAIRTYPE(K, V) item, map)` with `for (auto& item : map)` or `for (const auto& item : map)` to prevent redundant allocations and speed up iteration.
