## 2024-05-14 - Unnecessary String Copies in Network Loop
**Learning:** Legacy `BOOST_FOREACH` loops that do not use references (e.g., `BOOST_FOREACH(const std::string msg, allMessages)`) cause hidden deep copies of complex types on every iteration. In a high-throughput path like `ProcessMessage`, this results in excessive heap allocations per packet.
**Action:** Always inspect loop iteration variables for missing `&` when iterating over collections of complex types. Prefer standard library algorithms like `std::find` which cleanly avoid this issue by operating on iterators.
