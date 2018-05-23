// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"
#include "zerocoin_params.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "libzerocoin/bitcoin_bignum/bignum.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"

/**
 * Simple Miner
 */
#include "arith_uint256.h"
#include "primitives/block.h"
#include <iostream>

bool checkProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    // Check range
    if (fNegative || bnTarget == 0 || fOverflow)
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

void mineBlock(CBlock &block)
{
    while (!checkProofOfWork(block.GetPoWHash(0), block.nBits)) {
        block.nNonce++;
    }

    std::cout << "Hash: 0x" << block.GetHash().ToString() << std::endl;
    std::cout << "Merkle: 0x" << block.hashMerkleRoot.ToString() << std::endl;
    std::cout << "Nonce: " << block.nNonce << std::endl;
}


const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

static CBlock CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
                   uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    //CScriptNum csn = CScriptNum(4);
    //std::cout << "CScriptNum(4):" << csn.GetHex();
    //CBigNum cbn = CBigNum(4);
    //std::cout << "CBigNum(4):" << cbn.GetHex();
    txNew.vin[0].scriptSig = CScript() << 504365040 << CBigNum(4).getvch() << std::vector < unsigned char >
    ((const unsigned char *) pszTimestamp, (const unsigned char *) pszTimestamp + strlen(pszTimestamp)) << extraNonce;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}
/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
    const char *pszTimestamp = "Bitcoin hash: 00000000000000000043e9b341aba1b492927f3a063342ab1792297cbe7d296b";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,
                              extraNonce);
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
       strNetworkID = "main";

       consensus.nSubsidyHalvingInterval = 0; // Verticalcoin - Deactivated 
       consensus.nMajorityEnforceBlockUpgrade = 750;
       consensus.nMajorityRejectBlockOutdated = 950;
       consensus.nMajorityWindow = 1000;
       consensus.nMinNFactor = 10;
       consensus.nMaxNFactor = 30;

       consensus.nChainStartTime = 1526671733;
       consensus.BIP34Height = 1;
       consensus.BIP34Hash = uint256S("0x76444d50ee38b41f0d468d94dc73851d00f9d840f46d78069c092e3128d50920");
       consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

       // Mining diffuclty LWMA Algo
       consensus.LWMAAveragingWindow = 70;               // N = 70
       consensus.LWMAStartingBlock = 1;                  // Starts on Block LWMAAveragingWindow + 5
       consensus.PowTargetTimespan = 30 * 60;            // 30 minutes between retargets
       consensus.LWMAPowTargetSpacing = 2 * 60;          // 2 minute blocktime

       consensus.fPowAllowMinDifficultyBlocks = false;
       consensus.nRuleChangeActivationThreshold = 1916;  // 95% of 2016
       consensus.nMinerConfirmationWindow = 15;          // PowTargetTimespan / LWMAPowTargetSpacing

       consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
       consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1475020800; // January 1, 2008
       consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

                                                                                        // Deployment of BIP68, BIP112, and BIP113.
       consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
       consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800;       // May 1st, 2016
       consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;         // May 1st, 2017

                                                                                        // Deployment of SegWit (BIP141, BIP143, and BIP147)
       consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
       consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000;    // November 15th, 2016.
       consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000;      // November 15th, 2017.
       
       // The best chain should have at least this much work.
       consensus.nMinimumChainWork = uint256S("0x0");

       // vNode
       consensus.nVnodePaymentsStartBlock = HF_VNODE_PAYMENT_START;
       nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

       nPoolMaxTransactions = 3;
       nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
       strSporkPubKey = "047560EDFAECC55DF8CE4DCC7BE0887A3AE611FF171CF7A5948BCA012E6ED2CDBFF44F4862B2EFED1E2BE6A70D7AEBE64130926B336DEC2452DC06E27091A15F36";
       strVnodePaymentsPubKey = "04FB415FD3DB63A0CDAA0037A96BEDBD845A676BC4D9DA50A0AEA55C79EBF0C11712403E1E84F4DF5C5C551468DFD9AC7C537149E065E5851CB35206CF6BD8BF48";

       nDefaultPort = 54111;
       nPruneAfterHeight = 100000;

       /**
       * The message start string is designed to be unlikely to occur in normal data.
       * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
       `  * a large 32-bit integer with any alignment.
       */
       pchMessageStart[0] = 0x22;
       pchMessageStart[1] = 0xa1;
       pchMessageStart[2] = 0x43;
       pchMessageStart[3] = 0x10;

       std::vector<unsigned char> extraNonce(4);
       extraNonce[0] = 0x21;
       extraNonce[1] = 0x6a;
       extraNonce[2] = 0x82;
       extraNonce[3] = 0x11;

       // Updated the nTime to avoid any max tip age issues.
       genesis = CreateGenesisBlock(1526671733, 10937844, 0x1e0ffff0, 2, 0 * COIN, extraNonce);
       
       //std::cout << "MAIN" << std::endl;
       //mineBlock(genesis);
       //std::cout << genesis.GetHash().ToString() << std::endl;
        
       consensus.hashGenesisBlock = genesis.GetHash();
       
       assert(consensus.hashGenesisBlock == uint256S("0x76444d50ee38b41f0d468d94dc73851d00f9d840f46d78069c092e3128d50920"));
       assert(genesis.hashMerkleRoot == uint256S("0x723c399bcb2e73ab0d33175127fcd3e999312f425b02b8b738053879948e345a"));

       // DNSSeed 01 - ipv4 / ipv6 - removed until we found out whats wrong with it.
      // vSeeds.push_back(CDNSSeedData("vrtseed.ovh", "seed1.vertical.ovh", false));
       vFixedSeeds.clear();

       // Note that of those with the service bits flag, most only support a subset of possible options
       base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char >(1, 70);  // V
       base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char >(1, 132); // v
       base58Prefixes[SECRET_KEY]     = std::vector < unsigned char >(1, 5);   // 3
       base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container < std::vector < unsigned char > >();
       base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container < std::vector < unsigned char > >();

       vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

       fMiningRequiresPeers = false; 
       fDefaultConsistencyChecks = false;
       fRequireStandard = true;
       fMineBlocksOnDemand = false;
       fTestnetToBeDeprecatedFieldRPC = false;
      
       checkpointData = (CCheckpointData) {
          boost::assign::map_list_of
          (0, uint256S("0x76444d50ee38b41f0d468d94dc73851d00f9d840f46d78069c092e3128d50920")),
           1526671733, // * UNIX timestamp of last checkpoint block
             0,    // * total number of transactions between genesis and last checkpoint
                   //   (the tx=... number in the SetBestChain debug.log lines)
             0     // * estimated number of transactions per day after checkpoint
       };

	    
	    nSpendV15StartBlock = ZC_V1_5_STARTING_BLOCK;
	    nSpendV2ID_1 = ZC_V2_SWITCH_ID_1;
	    nSpendV2ID_10 = ZC_V2_SWITCH_ID_10;
	    nSpendV2ID_25 = ZC_V2_SWITCH_ID_25;
	    nSpendV2ID_50 = ZC_V2_SWITCH_ID_50;
	    nSpendV2ID_100 = ZC_V2_SWITCH_ID_100;
	    nModulusV2StartBlock = ZC_MODULUS_V2_START_BLOCK;
       nModulusV1MempoolStopBlock = ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK;
	    nModulusV1StopBlock = ZC_MODULUS_V1_STOP_BLOCK;
    }
};

static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
		strNetworkID = "test";
		consensus.nSubsidyHalvingInterval = 0;
		consensus.nMajorityEnforceBlockUpgrade = 51;
		consensus.nMajorityRejectBlockOutdated = 75;
		consensus.nMajorityWindow = 100;
		consensus.nMinNFactor = 10;
		consensus.nMaxNFactor = 30;
      consensus.nChainStartTime = 1526664990;
      consensus.BIP34Height = 227931;
		consensus.BIP34Hash = uint256S("0x");
		consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      
      // Mining diffuclty LWMA Algo
      consensus.LWMAAveragingWindow = 70;       // N = 70
      consensus.LWMAStartingBlock = 1;          // Starts on Block LWMAAveragingWindow + 5
      consensus.PowTargetTimespan = 30 * 60;    // 30 minutes between retargets
      consensus.LWMAPowTargetSpacing = 2 * 60;  // 2 minute blocktime
     
		consensus.fPowAllowMinDifficultyBlocks = true;
		consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
		consensus.nMinerConfirmationWindow = 15; // PowTargetTimespan / LWMAPowTargetSpacing
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

		// Deployment of BIP68, BIP112, and BIP113.
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

		// Deployment of SegWit (BIP141, BIP143, and BIP147)
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

		// The best chain should have at least this much work.
		consensus.nMinimumChainWork = uint256S("0x00");
		// Vnode params testnet
      consensus.nVnodePaymentsStartBlock = HF_VNODE_HEIGHT_TESTNET;
		nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet

		nPoolMaxTransactions = 3;
		nFulfilledRequestExpireTime = 5 * 60; // fulfilled requests expire in 5 minutes
		strSporkPubKey = "047560EDFAECC55DF8CE4DCC7BE0887A3AE611FF171CF7A5948BCA012E6ED2CDBFF44F4862B2EFED1E2BE6A70D7AEBE64130926B336DEC2452DC06E27091A15F36";
		strVnodePaymentsPubKey = "04FB415FD3DB63A0CDAA0037A96BEDBD845A676BC4D9DA50A0AEA55C79EBF0C11712403E1E84F4DF5C5C551468DFD9AC7C537149E065E5851CB35206CF6BD8BF48";


		nDefaultPort = 55123;
		nPruneAfterHeight = 1000;
		/**
		* btzc: testnet params
		* nTime: 1516133785
		* nNonce: 0
		*/
      pchMessageStart[0] = 0x22;
      pchMessageStart[1] = 0xa1;
      pchMessageStart[2] = 0x43;
      pchMessageStart[3] = 0x10;

      std::vector<unsigned char> extraNonce(4);
      extraNonce[0] = 0x21;
      extraNonce[1] = 0x6a;
      extraNonce[2] = 0x82;
      extraNonce[3] = 0x11;

		genesis = CreateGenesisBlock(1526664990 /*05/11/2018 @ 6:57am (UTC)*/, 2792888, 0x1e0ffff0, 2, 100 * COIN, extraNonce);
      
      //std::cout << "TEST" << std::endl;
      //mineBlock(genesis);
      //std::cout << genesis.GetHash().ToString() << std::endl;

		consensus.hashGenesisBlock = genesis.GetHash();

      //std::cout << "verticalcoin TEST genesisBlock hash: " << consensus.hashGenesisBlock.ToString() << std::endl;
      //std::cout << "verticalcoin TEST hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;
      //
      //assert(consensus.hashGenesisBlock == uint256S("0xd484c39dd1f4079e2cac70d3bcba2f3debb7821373cfc2491cba99ebb273ef98"));
      //assert(genesis.hashMerkleRoot == uint256S("0x7ceb3f5bf44af358e620cd9ba1e408de774a21affeeb1b3d24ca90129c10d271"));

		// nodes with support for servicebits filtering should be at the top
		// verticalcoin test seeds
		//vSeeds.push_back(CDNSSeedData("vertical.schulze.ovh", "vertical.schulze.ovh", false));
		vFixedSeeds.clear();
		vSeeds.clear();


		base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char >(1, 28);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char >(1, 178);
		base58Prefixes[SECRET_KEY] = std::vector < unsigned char >(1, 185);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > >();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > >();
		vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

		fMiningRequiresPeers = false;
		fDefaultConsistencyChecks = false;
		fRequireStandard = false;
		fMineBlocksOnDemand = false;
		fTestnetToBeDeprecatedFieldRPC = true;

      
		//checkpointData = (CCheckpointData) {
      //      boost::assign::map_list_of
      //          (0, uint256S("0xd484c39dd1f4079e2cac70d3bcba2f3debb7821373cfc2491cba99ebb273ef98")),
      //      1526664990,
      //      0,
      //      0
		//};



	    nSpendV15StartBlock = ZC_V1_5_TESTNET_STARTING_BLOCK;
	    nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
	    nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
	    nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
	    nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
	    nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
	    nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
       nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
	    nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;
    }
};

static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 0; // Verticalcoin - Deactivated 
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nChainStartTime = 1526021849;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

        // Mining diffuclty LWMA Algo
        consensus.LWMAAveragingWindow = 70;       // N = 70
        consensus.LWMAStartingBlock = 1;          // Starts on Block LWMAAveragingWindow + 5
        consensus.PowTargetTimespan = 30 * 60;    // 30 minutes between retargets
        consensus.LWMAPowTargetSpacing = 2 * 60;  // 2 minute blocktime
        
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");
        // Vnode code
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xb1;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xd3;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x08;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        
        genesis = CreateGenesisBlock(1526665037 /*05/11/2018 @ 6:57am (UTC)*/, 414098458, 0x1d00ffff, 1, 0 * COIN, extraNonce);
        
        //std::cout << "REG" << std::endl;
        //mineBlock(genesis);
       
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << "verticalcoin REGTEST genesisBlock hash: " << consensus.hashGenesisBlock.ToString() << std::endl;
        //std::cout << "verticalcoin REGTEST hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;

        //assert(consensus.hashGenesisBlock == uint256S("0x0080c7bf30bb2579ed9c93213475bf8fafc1f53807da908cde19cf405b9eb55b"));
        //assert(genesis.hashMerkleRoot == uint256S("0x25b361d60bc7a66b311e72389bf5d9add911c735102bcb6425f63aceeff5b7b8"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
        
        /*
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
                (0, uint256S("0x0080c7bf30bb2579ed9c93213475bf8fafc1f53807da908cde19cf405b9eb55b")),
            0,
            0,
            0
        };
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 178);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();

	    nSpendV15StartBlock = ZC_V1_5_TESTNET_STARTING_BLOCK;
	    nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
	    nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
	    nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
	    nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
	    nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
	    nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
        nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
	    nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) {
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
