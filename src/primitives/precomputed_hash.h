// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2017 The Verticalcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

static map<int, uint256> mapPoWHash;

#define  PRECOMPUTED_HASHES 1

const char *precomputedHash[PRECOMPUTED_HASHES] = {
        "0x76444d50ee38b41f0d468d94dc73851d00f9d840f46d78069c092e3128d50920"
};

void buildMapPoWHash() {
    for (int i=1; i<PRECOMPUTED_HASHES; i++) {
        mapPoWHash.insert(make_pair(i, uint256S(precomputedHash[i])));
    }
};
