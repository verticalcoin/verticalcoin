## 2026-06-25 - Prevent silent map copies in CWallet::GetAddressBalances
**Learning:** BOOST_FOREACH over a std::map silently copies elements (e.g., CWalletTx in GetAddressBalances) unless specifically structured with references, which introduces hidden heap allocations during wallet lookups.
**Action:** Replaced BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet) with C++11 range-based for loops using const references (for (const auto& walletEntry : mapWallet)) to eliminate unnecessary deep copies of CWalletTx objects.
