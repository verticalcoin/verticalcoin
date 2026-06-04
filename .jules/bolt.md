
## 2024-05-19 - Expensive Copies in Getters
**Learning:** Returning large vectors by value in C++ leads to expensive deep copies and unnecessary performance overhead. This was observed in `GetFullVnodeVector` which returns a `std::vector<CVnode>`.
**Action:** When working with getters for large vectors or collections in C++, ensure they return by `const reference` (e.g., `const std::vector<T>&`) to avoid expensive deep copies. Update call sites to use `const auto&` or `const std::vector<T>&` as well.

## 2024-05-19 - Thread Safety Trumps Micro-Optimizations
**Learning:** Returning a large mutable collection (e.g., `std::vector`) by reference from a global state manager (like `mnodeman` in a cryptocurrency node) is highly unsafe in a multithreaded environment. The original code intentionally returned a copy (a snapshot) to allow separate UI/RPC threads to iterate safely without locks. Changing this to return a reference introduces severe race conditions: if a network thread adds an item, the vector may reallocate its underlying memory, invalidating iterators and causing Segmentation Faults.
**Action:** Before optimizing away deep copies (e.g., by changing return by value to return by reference), always verify the concurrency model. In architectures where the data is globally mutable by background threads, returning a snapshot (copy) is a necessary safety mechanism unless a robust, long-lived locking strategy is implemented. Revert optimizations that compromise thread safety.
