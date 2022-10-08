// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <poc/poc.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(2);
    txNew.vin[0].scriptSig = CScript() << static_cast<unsigned int>(0)
        << CScriptNum(static_cast<int64_t>(nNonce)) << CScriptNum(static_cast<int64_t>(0))
        << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.vout[1].nValue = 0;
    txNew.vout[1].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime       = nTime;
    genesis.nBaseTarget = nBaseTarget;
    genesis.nNonce      = nNonce;
    genesis.nVersion    = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=8cec494f7f02ad, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=6b80acabaf0fef, nTime=1531292789, nBaseTarget=18325193796, nNonce=0, vtx=1)
 *   CTransaction(hash=6b80acabaf0fef, ver=1, vin.size=1, vout.size=2, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=25.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *     CTxOut(nValue=00.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 6/Jun/2020 The rebirth starts";
    const CScript genesisOutputScript = CScript() << ParseHex("048E794284AD7E4D776919BDA05CDD38447D89B436BDAF5F65EBE9D7AD3A0B084908B88162BB60B1AA5ED6542063A30FC9584A335F656A54CD9F66D6C6B742B67F55") << OP_CHECKSIG;
	
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBaseTarget, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BFSFundAddress = "3BEtpggqUyyB2UkWXdvCEMzZLSFp1ECrEH";
        consensus.BFSMicroClubAddress = "3FMHNmsVgZ946Nq9K9hyaFoNZMkCy4TzKQ";
        consensus.BFSFundAddressPool = {
            "3BEtpggqUyyB2UkWXdvCEMzZLSFp1ECrEH",
            "3EAJSq5z1LGTTuUfV6SxHBXZFwKkQRrD5F",
            "3FMHNmsVgZ946Nq9K9hyaFoNZMkCy4TzKQ",
            "3LZKmxYCP1UEforR3yov7bTLsPxHM21hsp"};
        assert(consensus.BFSFundAddressPool.find(consensus.BFSFundAddress) != consensus.BFSFundAddressPool.end());
        assert(consensus.BFSFundAddressPool.find(consensus.BFSMicroClubAddress) != consensus.BFSFundAddressPool.end());

        consensus.nPowTargetSpacing = 180;
        consensus.fPowNoRetargeting = false;
        consensus.nCapacityEvalWindow = 3360;            // About 1 week
        consensus.nSubsidyHalvingInterval = 525600;      // BFSCoin about 3 years.525600*180/(365*24*3600) = 3
        consensus.fAllowMinDifficultyBlocks = false;     // For test
        consensus.nRuleChangeActivationThreshold = 3192; // 95% of 3360
        consensus.nMinerConfirmationWindow = 3360;       // About 1 week

        consensus.BFSIP001PreMiningEndHeight = 0; // 21M * 10% = 2.1M, 2.1M/25=84000 (+1 for deprecated public test data)
        consensus.BFSIP001FundZeroLastHeight = 0; // End 1 month after 30 * 24 * 60 / 5 = 8640
        consensus.BFSIP001TargetSpacing = 180;      // 3 minutes. Subsidy halving interval 700000 blocks (300 => 5minutes,420000 blocks)
        consensus.BFSIP001FundRoyaltyForFixed = 50;         // 50‰ to fund
        consensus.BFSIP001MinerForLowestReward = 100;       // minimum 100‰ to miner (700‰ to fund)
        consensus.BFSIP001MiningRatio = 20 * COIN;
        consensus.BFSIP001MiningRatioStageFirst = 150 * 1024;  // 150 PB
        consensus.BFSIP001MiningRatioStageSecond = 500 * 1024; // 500 PB
        consensus.BFSIP001SmoothHeight = 1000;

        //BFSIP002
        consensus.BFSIP002Height = 14401;                  //Actived after a month
        consensus.BFSIP002BindPlotterActiveHeight = 14881; //after 1 days
        consensus.BFSIP002CheckRelayHeight = 17761;        //after 1 weeks
        consensus.BFSIP002LimitBindPlotterHeight = 17761;  //after 1 weeks

        //BFSIP003
        consensus.BFSIP003Height = 73000;

#ifdef CUSTOM_GENERATE_COINS
        consensus.BFSIP003GenerateStartHeight = 73240;
        consensus.BFSIP003GenerateEndHeight = 74700;   //about 3 day
        consensus.BFSIP003CheckTxEndHeight = 159400;   //Since 003Height about 6 month
        consensus.BFSIP003SpendRatio = 100;            // 100‰
        consensus.BFSIP003ExcessAmount = 32768 * COIN; //2^15
        consensus.BFSIP003GenerateAddress = {
            "32e4MsbFfV5rqscorEw1V3kxqdFhCo8has",
            "3KY4ATSSN7NC5mmyapn9WpG34YHmGh3kKo",
            "3GbkDtpH5oa7y59X6VPTYoa84yt1TsB8HB"};
        consensus.BFSIP003GenerateVinSig = {
            {"160014daabcb78676229cc8f43e20c07656882e3494e91", "32e4MsbFfV5rqscorEw1V3kxqdFhCo8has"},
            {"160014959a07f9b904f5bc8f9bebe75fe1147d2e4de647", "3KY4ATSSN7NC5mmyapn9WpG34YHmGh3kKo"},
            {"16001482a1380cf254a85c3968a47a05c13e3a4e46e332", "3GbkDtpH5oa7y59X6VPTYoa84yt1TsB8HB"}};
#endif

        consensus.BFSIP004Height = 230000;
        consensus.BFSIP004DisableAddress = {
            "32uq7qN1vYfT8U5oqt23bUzy6hXDnuBqCd",
            "3Jenw5aFsi4FizXRiGa63j4YC6f7vzwxTN"};

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0xb0;
        pchMessageStart[2] = 0xb0;
        pchMessageStart[3] = 0xd0;
        nDefaultPort = 9816;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 3;
        m_assumed_chain_state_size = 1;


        genesis = CreateGenesisBlock(1597585380, 0, poc::GetBaseTarget(180), 2, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x9a405597913a644b8d069c09a8762393fe9d6bf3a0ba18ba3eb9cd26e2454235"));
        assert(genesis.hashMerkleRoot == uint256S("0xda8377815c9af49ce33c14ccde5e769a028db55baafa93eca42d932462f319e3"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                {0, uint256S("0x9a405597913a644b8d069c09a8762393fe9d6bf3a0ba18ba3eb9cd26e2454235")},
                {20000, uint256S("0xc7d7eb3579ccb230011e0e14e2fa7f42dae6ca357427f18c2032271171f46c9d")},
                {40000, uint256S("0xd55514dfaf995809e12f7a04090c95a47f8374c7d7eefdc0fa8052e35567802a")},
                {60000, uint256S("ce7c1c9963f3c406f7aaa0fe70afcb13f80a00e32ea63e3a1ea4508819899157")},
                {80000, uint256S("9826b348a6ceec3f2de36a97e7a87913b6f80f872ed2d32712781027881a7456")},
                {100000, uint256S("5998f2befa7ba895ba7cf20c467814c5ed44ca50e6e5de354d5bf746313bee5e")},
                {150000, uint256S("77aeadc4d4615280fb42a0418e8a8ad0ed87b87e658d0e6ce64a5675a5f5e31b")},
                {200000, uint256S("f79b1a0ff10eb2d35786003ae207dc770219145380724fc23ccd86874e071f95")},
            }};

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 f79b1a0ff10eb2d35786003ae207dc770219145380724fc23ccd86874e071f95
            /* nTime    */ 1633251919,
            /* nTxCount */ 216589,
            /* dTxRate  */ 0.006225968668357804,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BFSFundAddress = "2N5HQTTevHUfbhWsXJrLKbcQax5xnQukwrr";
        consensus.BFSMicroClubAddress = "2N9jMsi9f8RYBvHgZrguY3ycGeuRN3UXD7G";
        consensus.BFSFundAddressPool = {
            "2N5HQTTevHUfbhWsXJrLKbcQax5xnQukwrr",
            "2N9jMsi9f8RYBvHgZrguY3ycGeuRN3UXD7G"};
        assert(consensus.BFSFundAddressPool.find(consensus.BFSFundAddress) != consensus.BFSFundAddressPool.end());
        assert(consensus.BFSFundAddressPool.find(consensus.BFSMicroClubAddress) != consensus.BFSFundAddressPool.end());

        consensus.nPowTargetSpacing = 180;
        consensus.fPowNoRetargeting = false;
        consensus.nCapacityEvalWindow = 3360;
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.fAllowMinDifficultyBlocks = false;
        consensus.nRuleChangeActivationThreshold = 3192; // 75% for testchains
        consensus.nMinerConfirmationWindow = 3360;

        consensus.BFSIP001PreMiningEndHeight = 0; // 21M * 1% = 0.21M, 0.21M/25=8400
        consensus.BFSIP001FundZeroLastHeight = 0;
        consensus.BFSIP001TargetSpacing = 180;
        consensus.BFSIP001FundRoyaltyForFixed = 50;           // 50‰
        consensus.BFSIP001MinerForLowestReward = 100; // minimum 100‰ to miner (700‰ to fund)
        consensus.BFSIP001MiningRatio = 20 * COIN;
        consensus.BFSIP001MiningRatioStageFirst = 150 * 1024;  // 150 PB
        consensus.BFSIP001MiningRatioStageSecond = 500 * 1024; // 500 PB
        consensus.BFSIP001SmoothHeight = 1000;

        //BFSIP002
        consensus.BFSIP002Height = 8001;                  //Actived after a month
        consensus.BFSIP002BindPlotterActiveHeight = 8101; //after 1 days
        consensus.BFSIP002CheckRelayHeight = 8201;        //after 1 weeks
        consensus.BFSIP002LimitBindPlotterHeight = 8301;  //after 1 weeks

        //BFSIP003
        consensus.BFSIP003Height = 54200;

#ifdef CUSTOM_GENERATE_COINS
        consensus.BFSIP003GenerateStartHeight = 57694;
        consensus.BFSIP003GenerateEndHeight = 59134; //about 3 day
        consensus.BFSIP003CheckTxEndHeight = 59866;
        consensus.BFSIP003SpendRatio = 100;           //100‰
        consensus.BFSIP003ExcessAmount = 2048 * COIN; // 2^11
        consensus.BFSIP003GenerateAddress = {
            "2N9DoAwg14dwtcXXQLK59Xt4s9QkS7iwQaD",
            "2MxZRcjazjDCbRN33SkB6YSHLgRBFvoNm5t"};
        consensus.BFSIP003GenerateVinSig = {
            {"160014948d045ae408d9bf60e69722af7a044d796b62ed", "2N9DoAwg14dwtcXXQLK59Xt4s9QkS7iwQaD"},
            {"1600147e1e83c15d3ed2a1bcaf608c2a64bcdf016cf3ef", "2MxZRcjazjDCbRN33SkB6YSHLgRBFvoNm5t"}};
#endif

        consensus.BFSIP004Height = 165000;
        consensus.BFSIP004DisableAddress.clear();

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x1e;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0xa0;
        pchMessageStart[3] = 0x08;
        nDefaultPort = 9733;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 3;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1597570980, 1, poc::GetBaseTarget(180), 2, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x5944a2ae723ce1ef0dbf6e572b2fe7b15dd1630b50e0090897ee71fbe81fa4d1"));
        assert(genesis.hashMerkleRoot == uint256S("0x7546161fe69ddecc05c6ab21d6f71f7115a4a6a14e749c3ca953ee7a805a604d"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.push_back("seed-url");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x5944a2ae723ce1ef0dbf6e572b2fe7b15dd1630b50e0090897ee71fbe81fa4d1")},
                {20000, uint256S("0x7af8c7b2707e59d92300df7a223c94697d1898870dd2d05cac4b1304aaf6bda1")},
                {40000, uint256S("0x7bba932884707d25039f4a6e7c392bee17392923dd06ff6b510fa48d4a54f20f")},
                {60000, uint256S("0x9741de92301aa8fc847fae55948ffdaa428b87e1c63192888ba7ea50c34ed33e")},
                {80000, uint256S("0x5330efac21675eaab07a76a90c0edef61ca6276664b05b1dc57a7f86206e3956")},
                {160000, uint256S("0xa55ec886da14f3ade48cc105018037cfcf217a53efab69cca68bc9fd088d1cc1")},
            }};

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 a55ec886da14f3ade48cc105018037cfcf217a53efab69cca68bc9fd088d1cc1
            /* nTime    */ 1633494812,
            /* nTxCount */ 160752,
            /* dTxRate  */ 0.005526457103845043,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;

        consensus.BFSFundAddress = "2MsYSvDs58EbUFseePyZhjF4LsuXBhWgt4G";
        consensus.BFSMicroClubAddress = "2N8gJLpB3nH52T2w9N6vkMu1aJoHzhoAt2C";
        consensus.BFSFundAddressPool = {
            "2MsYSvDs58EbUFseePyZhjF4LsuXBhWgt4G",
            "2N8gJLpB3nH52T2w9N6vkMu1aJoHzhoAt2C",
        };
        assert(consensus.BFSFundAddressPool.find(consensus.BFSFundAddress) != consensus.BFSFundAddressPool.end());

        consensus.nPowTargetSpacing = 180;
        consensus.fPowNoRetargeting = true;
        consensus.nCapacityEvalWindow = 144;
        consensus.nSubsidyHalvingInterval = 300;
        consensus.fAllowMinDifficultyBlocks = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144;

        consensus.BFSIP001PreMiningEndHeight = 0; // 21M * 0.01% = 0.0021M, 0.0021M/25=84
        consensus.BFSIP001FundZeroLastHeight = 0;
        consensus.BFSIP001TargetSpacing = 180;
        consensus.BFSIP001FundRoyaltyForFixed = 50;   // 50‰
        consensus.BFSIP001MinerForLowestReward = 100; // minimum 100‰ to miner (700‰ to fund)
        consensus.BFSIP001MiningRatio = 20 * COIN;
        consensus.BFSIP001MiningRatioStageFirst = 3;  // 3 TB
        consensus.BFSIP001MiningRatioStageSecond = 5; // 5 TB
        consensus.BFSIP001SmoothHeight = 80;

        //BFSIP002
        consensus.BFSIP002Height = 249;
        consensus.BFSIP002BindPlotterActiveHeight = 260;
        consensus.BFSIP002CheckRelayHeight = 320;
        consensus.BFSIP002LimitBindPlotterHeight = 350;

        //BFSIP003
        consensus.BFSIP003Height = 500;

#ifdef CUSTOM_GENERATE_COINS
        consensus.BFSIP003GenerateStartHeight = 0;
        consensus.BFSIP003GenerateEndHeight = 0;
        consensus.BFSIP003CheckTxEndHeight = 0;
        consensus.BFSIP003SpendRatio = 0;
        consensus.BFSIP003ExcessAmount = 0;
        consensus.BFSIP003GenerateAddress.clear();
        consensus.BFSIP003GenerateVinSig.clear();
#endif

        consensus.BFSIP004Height = 1000;
        consensus.BFSIP004DisableAddress.clear();

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xe6;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xb1;
        pchMessageStart[3] = 0xd6;

        nDefaultPort = 19733;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1598869525, 2, poc::GetBaseTarget(180), 2, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xa5957bd6056c533dbe922774c8762f857f42cfc5f1617720dee96b17d2ba94ae"));
        assert(genesis.hashMerkleRoot == uint256S("0x0c5a782c39e30155fd9f5b073129a90940df1260513bf5029a48a71cc50b7fca"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            {
                {0, uint256S("0xa5957bd6056c533dbe922774c8762f857f42cfc5f1617720dee96b17d2ba94ae")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
