## 2024-05-24 - Legacy Boost and C++13 in Tests
**Learning:** The test suite (`make check`) has unrelated compilation failures due to gcc 13 compatibility issues with legacy C++ (e.g., `boost::function` static_casts) and missing headers like `<deque>` in `httpserver.cpp`. These issues prevent running the full test suite.
**Action:** When making small optimizations in isolated files, rely on object-level compilation (e.g., `make -C src wallet/libbitcoin_wallet_a-wallet.o`) to verify the specific changes instead of failing due to global test suite bitrot.
