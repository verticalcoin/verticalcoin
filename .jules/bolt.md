## 2024-06-28 - Avoid deep copies in BOOST_FOREACH
**Learning:** Found legacy `BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)` loops that unintentionally perform deep copies by passing `PAIRTYPE(uint256, CWalletTx)` by value instead of reference `PAIRTYPE(const uint256, CWalletTx)&` or using modern C++11 range-based for loops `for (const auto& walletEntry : mapWallet)`.
**Action:** Always replace value-type `BOOST_FOREACH` over maps with range-based for loops with `const auto&` to prevent hidden copies of large types like `CWalletTx`.
