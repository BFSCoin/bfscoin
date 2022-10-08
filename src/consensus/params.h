// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <amount.h>
#include <atomic>
#include <uint256.h>
#include <limits>
#include <map>
#include <set>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    /** BFScoin Fund address */
    std::string BFSFundAddress;
    std::set<std::string> BFSFundAddressPool;

    /** BFScoin MicroClub address */
    std::string BFSMicroClubAddress;

    uint256 hashGenesisBlock;
    /** Subsidy halving interval blocks base on 600 seconds */
    int nSubsidyHalvingInterval;
    int nCapacityEvalWindow;

    /** BFSIP = BFScoin Improvement Proposals, like BIP */
    /** BFScoin target spacing */
    int BFSIP001TargetSpacing;
    /** BFScoin fund pre-mining height */
    int BFSIP001PreMiningEndHeight;
    /** BFScoin fund zero height */
    int BFSIP001FundZeroLastHeight;
    /** BFScoin fund royalty for fixed. 1000% */
    int BFSIP001FundRoyaltyForFixed;
    /** BFScoin miner for lowest reward. 1000% */
    int BFSIP001MinerForLowestReward;
    /** BFScoin miner mining ratio per TB */
    CAmount BFSIP001MiningRatio;
    int64_t BFSIP001MiningRatioStageFirst;
    int64_t BFSIP001MiningRatioStageSecond;
    int BFSIP001SmoothHeight;

    /** Block height at which BFSIP002 becomes active */
    int BFSIP002Height;
    int BFSIP002BindPlotterActiveHeight;
    int BFSIP002CheckRelayHeight;
    int BFSIP002LimitBindPlotterHeight;

    /** Block height at which BFSIP003 becomes active
        Adjust the calculation of the base target */
    int BFSIP003Height;

    #ifdef CUSTOM_GENERATE_COINS
    int BFSIP003GenerateStartHeight;
    int BFSIP003GenerateEndHeight;
    int BFSIP003CheckTxEndHeight;
    int BFSIP003SpendRatio;
    CAmount BFSIP003ExcessAmount;
    std::set<std::string> BFSIP003GenerateAddress;
    std::map<std::string, std::string> BFSIP003GenerateVinSig;
    #endif

    int BFSIP004Height;
    std::set<std::string> BFSIP004DisableAddress;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPocTargetTimespan / BFSIP001TargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    int nRuleChangeActivationThreshold;
    int nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Proof of Capacity parameters */
    bool fAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
};

// Get target time space
inline int GetTargetSpacing(int nHeight, const Params& params) {
    return params.BFSIP001TargetSpacing;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
