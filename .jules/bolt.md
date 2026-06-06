## 2024-06-06 - Map Lookup and String Pass-by-Value Optimization
**Learning:** Found an inefficiency in `CNetFulfilledRequestManager::HasFulfilledRequest` where `strRequest` was being passed by value (triggering a deep string copy) and there was a redundant map lookup: `it->second.find(strRequest)` followed by `it->second[strRequest]`.
**Action:** Use `const std::string&` for read-only string parameters and capture the iterator from `find()` to avoid performing double lookups in `std::map`.
