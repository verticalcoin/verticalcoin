## 2025-01-20 - [Optimize CWallet::GetAddressBalances]
**Learning:** Found an inefficient `BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)` loop that copies map entries by value, leading to unnecessary copying.
**Action:** Always replace value-based map iterations with const reference loops (`const auto&`) or C++11 range-based loops to prevent redundant allocations and deep copies.
