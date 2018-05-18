// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2017 The Verticalcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

static map<int, uint256> mapPoWHash;

#define  PRECOMPUTED_HASHES 1

const char *precomputedHash[PRECOMPUTED_HASHES] = {
        "0xd853097c7fb224ec51b285f9e9672b02d656d897e331667e8d6675c353e2a28d"
};

void buildMapPoWHash() {
    for (int i=1; i<PRECOMPUTED_HASHES; i++) {
        mapPoWHash.insert(make_pair(i, uint256S(precomputedHash[i])));
    }
};
