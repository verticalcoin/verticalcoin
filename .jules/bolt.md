## 2024-05-24 - Passing objects by const reference
**Learning:** Found several manager components taking `std::string` and `CAddress` by value. This causes an unnecessary string allocation and copy for every invocation, impacting memory and CPU cache locally.
**Action:** Always prefer `const T&` over pass-by-value for non-primitive types like `std::string` and container objects across codebase managers to reduce overhead.
