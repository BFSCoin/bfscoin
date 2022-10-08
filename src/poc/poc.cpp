// Copyright (c) 2017-2020 The BFScoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <chainparams.h>
#include <compat/endian.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/shabal256.h>
#include <key_io.h>
#include <logging.h>
#include <miner.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <threadinterrupt.h>
#include <timedata.h>
#include <ui_interface.h>
#include <util/time.h>
#include <util/validation.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif
#ifdef CUSTOM_GENERATE_COINS
#include <node/coin.h>
#endif

#include <cinttypes>
#include <cmath>
#include <exception>
#include <limits>
#include <string>
#include <tuple>
#include <unordered_map>

#include <event2/thread.h>

namespace {

// Generator
struct GeneratorState {
    uint64_t plotterId;
    uint64_t nonce;
    uint64_t best;
    int height;

    CTxDestination dest;
    std::shared_ptr<CKey> privKey;

    GeneratorState() : best(poc::INVALID_DEADLINE) { }
};
typedef std::unordered_map<uint64_t, GeneratorState> Generators; // Generation low 64bits -> GeneratorState
Generators mapGenerators GUARDED_BY(cs_main);

std::shared_ptr<CBlock> CreateBlock(const GeneratorState &generateState)
{
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(GetScriptForDestination(generateState.dest),
            generateState.plotterId, generateState.nonce, generateState.best / ::ChainActive().Tip()->nBaseTarget,
            generateState.privKey);
    } catch (std::exception &e) {
        const char *what = e.what();
        LogPrintf("CreateBlock() fail: %s\n", what ? what : "Catch unknown exception");
    }
    if (!pblocktemplate.get()) 
        return nullptr;

    CBlock *pblock = &pblocktemplate->block;
    return std::make_shared<CBlock>(*pblock);
}

// Mining loop
CThreadInterrupt interruptCheckDeadline;
std::thread threadCheckDeadline;
void CheckDeadlineThread()
{
    util::ThreadRename("bitcoin-checkdeadline");
    while (!interruptCheckDeadline) {
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(500)))
            break;

        std::shared_ptr<CBlock> pblock;
        CBlockIndex *pTrySnatchTip = nullptr;
        {
            LOCK(cs_main);
            if (!mapGenerators.empty()) {
                if (GetTimeOffset() > MAX_FUTURE_BLOCK_TIME) {
                    LogPrintf("Your computer time maybe abnormal (offset %" PRId64 "). " \
                        "Check your computer time or add -maxtimeadjustment=0 \n", GetTimeOffset());
                }
                int64_t nAdjustedTime = GetAdjustedTime();
                CBlockIndex *pindexTip = ::ChainActive().Tip();
                for (auto it = mapGenerators.cbegin(); it != mapGenerators.cend() && pblock == nullptr; ) {
                    if (pindexTip->GetNextGenerationSignature().GetUint64(0) == it->first) {
                        //! Current round
                        uint64_t deadline = it->second.best / pindexTip->nBaseTarget;
                        if (nAdjustedTime + 1 >= (int64_t)pindexTip->nTime + (int64_t)deadline) {
                            // Forge
                            LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                it->second.height, it->second.nonce, it->second.plotterId, deadline);
                            pblock = CreateBlock(it->second);
                            if (!pblock) {
                                LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                    it->second.height, it->second.nonce, it->second.plotterId, deadline);
                            } else {
                                LogPrint(BCLog::POC, "Created block: hash=%s, time=%d\n", pblock->GetHash().ToString(), pblock->nTime);
                            }
                        } else {
                            ++it;
                            continue;
                        }
                    } else if (pindexTip->GetGenerationSignature().GetUint64(0) == it->first) {
                        //! Previous round
                        // Process future post block (MAX_FUTURE_BLOCK_TIME). My deadline is best (highest chainwork).
                        uint64_t mineDeadline = it->second.best / pindexTip->pprev->nBaseTarget;
                        uint64_t tipDeadline = (uint64_t) (pindexTip->GetBlockTime() - pindexTip->pprev->GetBlockTime() - 1);
                        if (mineDeadline <= tipDeadline) {
                            LogPrint(BCLog::POC, "Snatch block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 " <= %" PRIu64 "\n",
                                it->second.height, it->second.nonce, it->second.plotterId, mineDeadline, tipDeadline);

                            //! Try snatch block
                            pTrySnatchTip = pindexTip;
                            break;
                        }
                    }

                    it = mapGenerators.erase(it);
                }

            } else {
                continue;
            }
        }

        //! Try snatch block
        if (pTrySnatchTip != nullptr) {
            assert(pblock == nullptr);
            CValidationState state;
            if (!InvalidateBlock(state, Params(), pTrySnatchTip)) {
                LogPrint(BCLog::POC, "Snatch block fail: invalidate %s got\n\t%s\n", pTrySnatchTip->ToString(), state.GetRejectReason());
            } else {
                {
                    LOCK(cs_main);
                    ResetBlockFailureFlags(pTrySnatchTip);

                    auto itDummyProof = mapGenerators.find(pTrySnatchTip->GetGenerationSignature().GetUint64(0));
                    if (itDummyProof != mapGenerators.end()) {
                        pblock = CreateBlock(itDummyProof->second);
                        if (!pblock) {
                            LogPrintf("Snatch block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 "\n",
                                itDummyProof->second.height, itDummyProof->second.nonce, itDummyProof->second.plotterId);
                        } else if (GetBlockProof(*pblock, Params().GetConsensus()) <= GetBlockProof(*pTrySnatchTip, Params().GetConsensus())) {
                            //! Lowest chainwork, give up
                            LogPrintf("Snatch block give up: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 "\n",
                                itDummyProof->second.height, itDummyProof->second.nonce, itDummyProof->second.plotterId);
                            pblock.reset();
                        } else {
                            LogPrint(BCLog::POC, "Snatch block success: height=%d, hash=%s\n", itDummyProof->second.height, pblock->GetHash().ToString());
                        }
                    }
                    mapGenerators.erase(itDummyProof);
                }

                //! Reset best
                if (!ActivateBestChain(state, Params())) {
                    LogPrintf("Activate best chain fail: %s\n", __func__, FormatStateMessage(state));
                    assert (false);
                }
            }
        }

        if (pblock && !ProcessNewBlock(Params(), pblock, true, nullptr))
            LogPrintf("%s: Process new block fail %s\n", __func__, pblock->ToString());
    }

    LogPrintf("Exit PoC forge thread\n");
}

// Save block signature require private key
typedef std::unordered_map< uint64_t, std::shared_ptr<CKey> > CPrivKeyMap;
CPrivKeyMap mapSignaturePrivKeys;

// 4398046511104 / 240 = 18325193796
const uint64_t BFS_BASE_TARGET_240 = 18325193796ull;

// 4398046511104 / 300 = 14660155037
const uint64_t BFS_BASE_TARGET_300 = 14660155037ull;

// 4398046511104 / 180 = 24433591728
const uint64_t BFS_BASE_TARGET_180 = 24433591728ull;

}

namespace poc {

static constexpr int HASH_SIZE = 32;
static constexpr int HASHES_PER_SCOOP = 2;
static constexpr int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE; // 2 hashes per scoop
static constexpr int SCOOPS_PER_PLOT = 4096;
static constexpr int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE; // 256KB
static std::unique_ptr<unsigned char> calcDLDataCache(new unsigned char[PLOT_SIZE + 16]); // Global calc cache

//! Thread safe
static uint64_t CalcDL(int nHeight, const uint256& generationSignature, const uint64_t& nPlotterId, const uint64_t& nNonce, const Consensus::Params& params) {
    CShabal256 shabal256;
    uint256 temp;

    // Row data
    const uint64_t plotterId_be = htobe64(nPlotterId);
    const uint64_t nonce_be = htobe64(nNonce);
    unsigned char *const data = calcDLDataCache.get();
    memcpy(data + PLOT_SIZE, (const unsigned char*)&plotterId_be, 8);
    memcpy(data + PLOT_SIZE + 8, (const unsigned char*)&nonce_be, 8);
    for (int i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        int len = PLOT_SIZE + 16 - i;
        if (len > SCOOPS_PER_PLOT) {
            len = SCOOPS_PER_PLOT;
        }

        shabal256
            .Write(data + i, len)
            .Finalize(data + i - HASH_SIZE);
    }
    // Final
    shabal256
        .Write(data, PLOT_SIZE + 16)
        .Finalize(temp.begin());
    for (int i = 0; i < PLOT_SIZE; i++) {
        data[i] = (unsigned char) (data[i] ^ (temp.begin()[i % HASH_SIZE]));
    }

    // Scoop
    const uint64_t height_be = htobe64(static_cast<uint64_t>(nHeight));
    shabal256
        .Write(generationSignature.begin(), generationSignature.size())
        .Write((const unsigned char*)&height_be, 8)
        .Finalize((unsigned char*)temp.begin());
    const uint32_t scoop = (uint32_t) (temp.begin()[31] + 256 * temp.begin()[30]) % 4096;

    // PoC2 Rearrangement. Swap high hash
    //
    // [0] [1] [2] [3] ... [N-1]
    // [1] <-> [N-1]
    // [2] <-> [N-2]
    // [3] <-> [N-3]
    //
    // Only care hash data of scoop index
    memcpy(data + scoop * SCOOP_SIZE + HASH_SIZE, data + (SCOOPS_PER_PLOT - scoop) * SCOOP_SIZE - HASH_SIZE, HASH_SIZE);

    // Result
    shabal256
        .Write(generationSignature.begin(), generationSignature.size())
        .Write(data + scoop * SCOOP_SIZE, SCOOP_SIZE)
        .Finalize(temp.begin());
    return temp.GetUint64(0);
}

//! Thread unsafe
static uint64_t CalculateUnformattedDeadline(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    // Fund
    if (prevBlockIndex.nHeight + 1 <= params.BFSIP001PreMiningEndHeight)
        return 0;

    // BFSIP002 disallow plotter 0
    if (block.nPlotterId == 0 && prevBlockIndex.nHeight + 1 >= params.BFSIP002Height)
        return poc::INVALID_DEADLINE;

    // Regtest use nonce as deadline
    if (params.fAllowMinDifficultyBlocks)
        return block.nNonce * prevBlockIndex.nBaseTarget;

    return CalcDL(prevBlockIndex.nHeight + 1, prevBlockIndex.GetNextGenerationSignature(), block.nPlotterId, block.nNonce, params);
}

// Require hold cs_main
uint64_t CalculateDeadline(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    return CalculateUnformattedDeadline(prevBlockIndex, block, params) / prevBlockIndex.nBaseTarget;
}

uint64_t CalculateBaseTarget(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    int nHeight = prevBlockIndex.nHeight + 1;
    if (nHeight < params.BFSIP001PreMiningEndHeight + 4) {
        // genesis block & pre-mining block & const block
        return BFS_BASE_TARGET_180;
    } else if (nHeight < params.BFSIP001PreMiningEndHeight + 2700) {
        // [N-1,N-2,N-3,N-4]
        const int N = 4;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        uint64_t avgBaseTarget = pLastindex->nBaseTarget;
        for (int n = 1; n < N; n++) {
            pLastindex = pLastindex->pprev;
            avgBaseTarget += pLastindex->nBaseTarget;
        }
        avgBaseTarget /= N;

        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        uint64_t curBaseTarget = avgBaseTarget;
        uint64_t newBaseTarget = (curBaseTarget * diffTime) / (params.BFSIP001TargetSpacing * 4);
        if (newBaseTarget > BFS_BASE_TARGET_180) {
            newBaseTarget = BFS_BASE_TARGET_180;
        }
        if (newBaseTarget < (curBaseTarget * 9 / 10)) {
            newBaseTarget = curBaseTarget * 9 / 10;
        }
        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }
        if (newBaseTarget > (curBaseTarget * 11 / 10)) {
            newBaseTarget = curBaseTarget * 11 / 10;
        }

        return newBaseTarget;
    } else if (nHeight < params.BFSIP003Height) {
        // [N-1,N-2,...,N-24,N-25]
        const int N = 24;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        uint64_t avgBaseTarget = pLastindex->nBaseTarget;
        for (int n = 1; n <= N; n++) {
            pLastindex = pLastindex->pprev;
            avgBaseTarget = (avgBaseTarget * n + pLastindex->nBaseTarget) / (n + 1);
        }
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.BFSIP001TargetSpacing * N;
        if (diffTime < targetTimespan / 2) {
            diffTime = targetTimespan / 2;
        }
        if (diffTime > targetTimespan * 2) {
            diffTime = targetTimespan * 2;
        }
        uint64_t curBaseTarget = prevBlockIndex.nBaseTarget;
        uint64_t newBaseTarget = avgBaseTarget * diffTime / targetTimespan;
        if (newBaseTarget > BFS_BASE_TARGET_180) {
            newBaseTarget = BFS_BASE_TARGET_180;
        }
        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }
        if (newBaseTarget < curBaseTarget * 8 / 10) {
            newBaseTarget = curBaseTarget * 8 / 10;
        }
        if (newBaseTarget > curBaseTarget * 12 / 10) {
            newBaseTarget = curBaseTarget * 12 / 10;
        }

        return newBaseTarget;
    } else {
        //  [N-1,N-2,...,N-79,N-80] // About 4 hours
        const int N = 80;
        const CBlockIndex* pLastindex = &prevBlockIndex;
        uint64_t avgBaseTarget = pLastindex->nBaseTarget;
        for (int n = 1; n < N; n++) {
            pLastindex = pLastindex->pprev;
            avgBaseTarget = (avgBaseTarget * n + pLastindex->nBaseTarget) / (n + 1);
        }
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.BFSIP001TargetSpacing * N;
        if (diffTime < targetTimespan / 2) {
            diffTime = targetTimespan / 2;
        }
        if (diffTime > targetTimespan * 2) {
            diffTime = targetTimespan * 2;
        }
        uint64_t curBaseTarget = prevBlockIndex.nBaseTarget;
        uint64_t newBaseTarget = avgBaseTarget * diffTime / targetTimespan;
        if (newBaseTarget > BFS_BASE_TARGET_180) {
            newBaseTarget = BFS_BASE_TARGET_180;
        }
        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }
        if (newBaseTarget < curBaseTarget * 8 / 10) {
            newBaseTarget = curBaseTarget * 8 / 10;
        }
        if (newBaseTarget > curBaseTarget * 12 / 10) {
            newBaseTarget = curBaseTarget * 12 / 10;
        }

        return newBaseTarget;
    }
}

uint64_t GetBaseTarget(int nHeight, const Consensus::Params& params) {
    return GetBaseTarget(Consensus::GetTargetSpacing(nHeight, params));
}

uint64_t AddNonce(uint64_t& bestDeadline, const CBlockIndex& miningBlockIndex,
    const uint64_t& nNonce, const uint64_t& nPlotterId, const std::string& generateTo,
    bool fCheckBind, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);

    if (interruptCheckDeadline)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Not run in mining mode, restart by -server");

    CBlockHeader block;
    block.nPlotterId = nPlotterId;
    block.nNonce     = nNonce;
    const uint64_t calcUnformattedDeadline = CalculateUnformattedDeadline(miningBlockIndex, block, params);
    if (calcUnformattedDeadline == INVALID_DEADLINE)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid deadline");

    const uint64_t calcDeadline = calcUnformattedDeadline / miningBlockIndex.nBaseTarget;
    LogPrint(BCLog::POC, "Add nonce: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
        miningBlockIndex.nHeight + 1, nNonce, nPlotterId, calcDeadline);
    bestDeadline = calcDeadline;
    bool fNewBest = false;
    if (miningBlockIndex.nHeight >= ::ChainActive().Height() - 1) {
        // Only tip and previous block
        auto it = mapGenerators.find(miningBlockIndex.GetNextGenerationSignature().GetUint64(0));
        if (it != mapGenerators.end()) {
            if (it->second.best > calcUnformattedDeadline) {
                fNewBest = true;
            } else {
                fNewBest = false;
                bestDeadline = it->second.best / miningBlockIndex.nBaseTarget;
            }
        } else {
            fNewBest = true;
        }
    }

    if (fNewBest) {
        CTxDestination dest;
        std::shared_ptr<CKey> privKey;
        if (generateTo.empty()) {
            // Update generate address from wallet
        #ifdef ENABLE_WALLET
            auto pwallet = HasWallets() ? GetWallets()[0] : nullptr;
            if (!pwallet)
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require generate destination address or private key");
            dest = pwallet->GetPrimaryDestination();
        #else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require generate destination address or private key");
        #endif
        } else {
            dest = DecodeDestination(generateTo);
            if (!boost::get<ScriptHash>(&dest)) {
                // Maybe privkey
                CKey key = DecodeSecret(generateTo);
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid generate destination address or private key");
                } else {
                    privKey = std::make_shared<CKey>(key);
                    // P2SH-Segwit
                    CKeyID keyid = privKey->GetPubKey().GetID();
                    CTxDestination segwit = WitnessV0KeyHash(keyid);
                    dest = ScriptHash(GetScriptForDestination(segwit));
                }
            }
        }
        if (!boost::get<ScriptHash>(&dest))
            throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid BFScoin address");

        // Check bind
        if (miningBlockIndex.nHeight + 1 >= params.BFSIP002BindPlotterActiveHeight) {
            const CAccountID accountID = ExtractAccountID(dest);
            if (accountID.IsNull())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BFScoin address");
            if (!::ChainstateActive().CoinsTip().HaveActiveBindPlotter(accountID, nPlotterId))
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    strprintf("%" PRIu64 " with %s not active bind", nPlotterId, EncodeDestination(dest)));
        }

        // Update private key for signature. Pre-set
        if (miningBlockIndex.nHeight + 1 >= params.BFSIP002LimitBindPlotterHeight) {
            uint64_t destId = boost::get<ScriptHash>(&dest)->GetUint64(0);

            // From cache
            if (!privKey && mapSignaturePrivKeys.count(destId))
                privKey = mapSignaturePrivKeys[destId];

            // From wallets
        #ifdef ENABLE_WALLET
            if (!privKey) {
                for (auto pwallet : GetWallets()) {
                    CKeyID keyid = GetKeyForDestination(*pwallet, dest);
                    if (!keyid.IsNull()) {
                        CKey key;
                        if (pwallet->GetKey(keyid, key)) {
                            privKey = std::make_shared<CKey>(key);
                            break;
                        }
                    }
                }
            }
        #endif

            if (!privKey)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("Please pre-set %s private key for mining-sign. The consensus verify at %d.", EncodeDestination(dest), params.BFSIP002LimitBindPlotterHeight));

            if (!mapSignaturePrivKeys.count(destId))
                mapSignaturePrivKeys[destId] = privKey;
        }

        // Update best
        GeneratorState &generatorState = mapGenerators[miningBlockIndex.GetNextGenerationSignature().GetUint64(0)];
        generatorState.plotterId = nPlotterId;
        generatorState.nonce     = nNonce;
        generatorState.best      = calcUnformattedDeadline;
        generatorState.height    = miningBlockIndex.nHeight + 1;
        generatorState.dest      = dest;
        generatorState.privKey   = privKey;

        LogPrint(BCLog::POC, "New best deadline %" PRIu64 ".\n", calcDeadline);

        uiInterface.NotifyBestDeadlineChanged(generatorState.height, generatorState.plotterId, generatorState.nonce, calcDeadline);
    }

    return calcDeadline;
}

CBlockList GetEvalBlocks(int nHeight, bool fAscent, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    assert(nHeight >= 0 && nHeight <= ::ChainActive().Height());

    CBlockList vBlocks;
    int nBeginHeight = std::max(nHeight - params.nCapacityEvalWindow + 1, params.BFSIP001PreMiningEndHeight + 1);
    if (nHeight >= nBeginHeight) {
        vBlocks.reserve(nHeight - nBeginHeight + 1);
        if (fAscent) {
            for (int height = nBeginHeight; height <= nHeight; height++) {
                vBlocks.push_back(std::cref(*(::ChainActive()[height])));
            }
        } else {
            for (int height = nHeight; height >= nBeginHeight; height--) {
                vBlocks.push_back(std::cref(*(::ChainActive()[height])));
            }
        }
    }
    return vBlocks;
}

int64_t GetNetCapacity(int nHeight, const Consensus::Params& params)
{
    uint64_t nBaseTarget = 0;
    int nBlockCount = 0;
    for (const CBlockIndex& block : GetEvalBlocks(nHeight, true, params)) {
    	nBaseTarget += block.nBaseTarget;
    	nBlockCount++;
    }
    if (nBlockCount != 0) {
        nBaseTarget /= nBlockCount;
        if (nBaseTarget != 0) {
            const uint64_t& nInitbaseTarget = GetTargetSpacing(nHeight, params);
            return std::max(static_cast<int64_t>(nInitbaseTarget / nBaseTarget), (int64_t) 1);
        }
    }

    return (int64_t) 1;
}

template <uint64_t BT>
static int64_t EvalNetCapacity(int nHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    uint64_t nBaseTarget = 0;
    int nBlockCount = 0;
    for (const CBlockIndex& block : GetEvalBlocks(nHeight, true, params)) {
        // All blocks
        associateBlock(block);

        nBaseTarget += block.nBaseTarget;
        nBlockCount++;
    }

    if (nBlockCount != 0) {
        nBaseTarget /= nBlockCount;
        if (nBaseTarget != 0) {
            return std::max(static_cast<int64_t>(BT / nBaseTarget), (int64_t) 1);
        }
    }

    return (int64_t) 1;
}

int64_t GetNetCapacity(int nHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    return EvalNetCapacity<BFS_BASE_TARGET_180>(nHeight, params, associateBlock);
}

#ifdef CUSTOM_GENERATE_COINS
CBlockList GetEvalBlocks(int nBeginHeight, int nMiddleHeight, int nEndHeight, 
    const Consensus::Params& params, std::function<bool(const CBlock& block)> associateBlock)
{
    AssertLockHeld(cs_main);
    assert(nBeginHeight <= nMiddleHeight);
    assert(nMiddleHeight <= nEndHeight);

    CBlockList vBlocks;
    if (::ChainActive().Height() >= nBeginHeight) {
        nEndHeight = std::min(nEndHeight, ::ChainActive().Height());
        if (nBeginHeight <= nEndHeight) {
            vBlocks.reserve(nEndHeight - nBeginHeight + 1);


            for (int height = nBeginHeight; height <= nEndHeight; height++) {
                const CBlockIndex& blockIndex = std::cref(*(::ChainActive()[height]));

                if (height <= nMiddleHeight) {
                    vBlocks.push_back(blockIndex);
                }

                if (blockIndex.nTx <= 1)
                    continue;

                CBlock block;
                if (IsBlockPruned(&blockIndex))
                    continue;

                if (!ReadBlockFromDisk(block, &blockIndex, params))
                    continue;

                if (associateBlock(block)) {
                    vBlocks.push_back(blockIndex);
                }
            }
        }
    }
    return vBlocks;
}

CAmount GetExcessBalanceOfAccountID(const CAccountID& accountID, CAmount* pSpendBalance, const Consensus::Params& params)
{
    CAmount balance = 0;
    if (pSpendBalance != nullptr) *pSpendBalance = 0;
    if (::ChainActive().Height() >= params.BFSIP003GenerateStartHeight) {
        std::string mineAddress = EncodeDestination(ScriptHash(accountID));
        if (params.BFSIP003GenerateAddress.count(mineAddress)) {
            for (const CBlockIndex& blockIndex : GetEvalBlocks(params.BFSIP003GenerateStartHeight, params.BFSIP003GenerateEndHeight,
                     params.BFSIP003CheckTxEndHeight, params,
                     [&pSpendBalance, &mineAddress, &accountID, &params](const CBlock& block) -> bool {
                         if (pSpendBalance != nullptr) {
                             for (const auto& tx : block.vtx) {
                                 if (tx->IsCoinBase())
                                     continue;

                                 const std::string scriptSig = HexStr(tx->vin[0].scriptSig);
                                 if ((params.BFSIP003GenerateVinSig.find(scriptSig) != params.BFSIP003GenerateVinSig.end()) &&
                                     (mineAddress == params.BFSIP003GenerateVinSig.at(scriptSig))) {
                                     for (const auto& out : tx->vout) {
                                         if (ExtractAccountID(out.scriptPubKey) != accountID)
                                             *pSpendBalance += out.nValue;
                                     }
                                 }
                             }
                         }
                         return false;
                     })) {
                if (blockIndex.generatorAccountID == accountID) {
                    balance += params.BFSIP003ExcessAmount;
                }
            }
        }
    }

    return balance;
}
#endif

int64_t GetRatioNetCapacity(int64_t nNetCapacityTB, int64_t nPrevNetCapacityTB, const Consensus::Params& params)
{
    int64_t nTargetNetCapacityTB;
    if (nNetCapacityTB > nPrevNetCapacityTB * 12 / 10) {
        nTargetNetCapacityTB = std::max(nPrevNetCapacityTB * 12 / 10, (int64_t) 1);
    } else if (nNetCapacityTB < nPrevNetCapacityTB * 8 / 10) {
        nTargetNetCapacityTB = std::max(nPrevNetCapacityTB * 8 / 10, (int64_t) 1);
    } else {
        nTargetNetCapacityTB = std::max(nNetCapacityTB, (int64_t) 1);
    }
    return nTargetNetCapacityTB;
}

// Round to cent coin. 0.0001
static const CAmount ratio_precise = COIN / 10000;
static inline CAmount RoundPledgeRatio(CAmount amount)
{
    return ((amount + ratio_precise / 2) / ratio_precise) * ratio_precise;
}

CAmount EvalMiningRatio(int nMiningHeight, int64_t nNetCapacityTB, const Consensus::Params& params, int* pRatioStage)
{
    // Dynamic
    if (nMiningHeight < params.BFSIP001SmoothHeight) {
        if (pRatioStage) *pRatioStage = -2;
        return params.BFSIP001MiningRatio;
    } else if (nNetCapacityTB < params.BFSIP001MiningRatioStageFirst) {
        if (pRatioStage) *pRatioStage = -1;
        return params.BFSIP001MiningRatio;
    } else if (nNetCapacityTB < params.BFSIP001MiningRatioStageSecond) {
        if (pRatioStage) *pRatioStage = 1;
        return params.BFSIP001MiningRatio / 2;
    }

    if (pRatioStage) *pRatioStage = 2;
    return params.BFSIP001MiningRatio / 4;
}

CAmount GetMiningRatio(int nMiningHeight, const Consensus::Params& params, int* pRatioStage,
    int64_t* pRatioCapacityTB, int *pRatioBeginHeight)
{
    AssertLockHeld(cs_main);
    assert(nMiningHeight > 0 && nMiningHeight <= ::ChainActive().Height() + 1);

    int64_t nNetCapacityTB = 0;
    nNetCapacityTB = GetNetCapacity(nMiningHeight - 1, params);

    if (pRatioCapacityTB) *pRatioCapacityTB = nNetCapacityTB;
    if (pRatioBeginHeight) *pRatioBeginHeight = std::max(nMiningHeight - params.nCapacityEvalWindow, params.BFSIP001PreMiningEndHeight + 1);
    return EvalMiningRatio(nMiningHeight, nNetCapacityTB, params, pRatioStage);
}

CAmount GetCapacityRequireBalance(int64_t nCapacityTB, CAmount miningRatio)
{
    return ((miningRatio * nCapacityTB + COIN/2) / COIN) * COIN;
}

// Compatible BFS002 before consensus
static inline CAmount GetCompatiblePledgeRatio(int nMiningHeight, const Consensus::Params& params)
{
	if (nMiningHeight < params.BFSIP001SmoothHeight) {
        return params.BFSIP001MiningRatio;
    }

    //static uint64_t nStoredCountFirst = 0;
    //static uint64_t nStoredCountSecond = 0;
    const int64_t nNetCapacity = GetNetCapacity(nMiningHeight - 1, params);
    if (nNetCapacity < params.BFSIP001MiningRatioStageFirst) {
        return params.BFSIP001MiningRatio;
    } else if (nNetCapacity < params.BFSIP001MiningRatioStageSecond) {
        return params.BFSIP001MiningRatio / 2;
    }

    return params.BFSIP001MiningRatio / 4;
}

// Compatible BFS002 before consensus
static inline int64_t GetCompatibleNetCapacity(int nMiningHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    return EvalNetCapacity<BFS_BASE_TARGET_180>(nMiningHeight - 1, params, associateBlock);
}

CAmount GetMiningRequireBalance(const CAccountID& generatorAccountID, const uint64_t& nPlotterId, int nMiningHeight,
    const CCoinsViewCache& view, int64_t* pMinerCapacity, CAmount* pOldMiningRequireBalance,
    const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    assert(GetSpendHeight(view) == nMiningHeight);

    if (pMinerCapacity != nullptr) *pMinerCapacity = 0;
    if (pOldMiningRequireBalance != nullptr) *pOldMiningRequireBalance = 0;

    const CAmount miningRatio = GetCompatiblePledgeRatio(nMiningHeight, params);

    int64_t nNetCapacityTB = 0;
    int nBlockCount = 0, nMinedCount = 0;
    if (nMiningHeight < params.BFSIP002BindPlotterActiveHeight) {
        // Mined by plotter ID
        int nOldMinedCount = 0;
        nNetCapacityTB = GetCompatibleNetCapacity(nMiningHeight, params,
            [&nBlockCount, &nMinedCount, &nOldMinedCount, &generatorAccountID, &nPlotterId] (const CBlockIndex &block) {
                nBlockCount++;

                // 1. Multi plotter generate to same wallet (like pool)
                // 2. Same plotter generate to multi wallets (for decrease point)
                if (block.generatorAccountID == generatorAccountID || block.nPlotterId == nPlotterId) {
                    nMinedCount++;

                    if (block.generatorAccountID != generatorAccountID) {
                        // Old consensus: multi mining. Plotter ID bind to multi miner
                        nOldMinedCount = -1;
                    } else if (nOldMinedCount != -1) {
                        nOldMinedCount++;
                    }
                }
            }
        );

        // Old consensus point
        if (pOldMiningRequireBalance != nullptr && nBlockCount > 0) {
            if (nOldMinedCount == -1) {
                // Multi mining
                *pOldMiningRequireBalance = MAX_MONEY;
            } else if (nOldMinedCount > 0) {
                int64_t nOldMinerCapacityTB = std::max((nNetCapacityTB * nOldMinedCount) / nBlockCount, (int64_t) 1);
                *pOldMiningRequireBalance = GetCapacityRequireBalance(nOldMinerCapacityTB, miningRatio);
            }
        }
    } else {
        // Binded plotter
        const std::set<uint64_t> plotters = view.GetAccountBindPlotters(generatorAccountID);
        nNetCapacityTB = GetCompatibleNetCapacity(nMiningHeight, params,
            [&nBlockCount, &nMinedCount, &plotters] (const CBlockIndex &block) {
                nBlockCount++;

                if (plotters.count(block.nPlotterId))
                    nMinedCount++;
            }
        );
        // Remove sugar
        if (nMinedCount < nBlockCount) nMinedCount++;
    }
    if (nMinedCount == 0 || nBlockCount == 0)
        return MAX_MONEY;

    int64_t nMinerCapacityTB = std::max((nNetCapacityTB * nMinedCount) / nBlockCount, (int64_t) 1);
    if (pMinerCapacity != nullptr) *pMinerCapacity = nMinerCapacityTB;
    return GetCapacityRequireBalance(nMinerCapacityTB, miningRatio);
}

bool CheckProofOfCapacity(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    uint64_t deadline = CalculateDeadline(prevBlockIndex, block, params);

    // Maybe overflow on arithmetic operation
    if (deadline > poc::MAX_TARGET_DEADLINE)
        return false;

    if (prevBlockIndex.nHeight + 1 < params.BFSIP002LimitBindPlotterHeight) {
        return deadline == 0 || block.GetBlockTime() > prevBlockIndex.GetBlockTime() + static_cast<int64_t>(deadline);
    } else {
        return block.GetBlockTime() == prevBlockIndex.GetBlockTime() + static_cast<int64_t>(deadline) + 1;
    }
}

CTxDestination AddMiningSignaturePrivkey(const CKey& key)
{
    LOCK(cs_main);

    std::shared_ptr<CKey> privKeyPtr = std::make_shared<CKey>(key);
    CKeyID keyid = privKeyPtr->GetPubKey().GetID();
    CTxDestination segwit = WitnessV0KeyHash(keyid);
    CTxDestination dest = ScriptHash(GetScriptForDestination(segwit));
    mapSignaturePrivKeys[boost::get<ScriptHash>(&dest)->GetUint64(0)] = privKeyPtr;
    return dest;
}

std::vector<CTxDestination> GetMiningSignatureAddresses()
{
    LOCK(cs_main);

    std::vector<CTxDestination> addresses;
    addresses.reserve(mapSignaturePrivKeys.size());
    for (auto it = mapSignaturePrivKeys.cbegin(); it != mapSignaturePrivKeys.cend(); it++) {
        CKeyID keyid = it->second->GetPubKey().GetID();
        CTxDestination segwit = WitnessV0KeyHash(keyid);
        CTxDestination dest = ScriptHash(GetScriptForDestination(segwit));
        addresses.push_back(dest);
    }

    return addresses;
}

}

bool StartPOC()
{
    LogPrintf("Starting PoC module\n");
    interruptCheckDeadline.reset();
    if (gArgs.GetBoolArg("-server", false)) {
        LogPrintf("Starting PoC forge thread\n");
        threadCheckDeadline = std::thread(CheckDeadlineThread);

        // import private key
        if (gArgs.IsArgSet("-signprivkey")) {
            for (const std::string &privkey : gArgs.GetArgs("-signprivkey")) {
                std::string strkeyLog = (privkey.size() > 2 ? privkey.substr(0, 2) : privkey) + "**************************************************";
                CTxDestination dest = poc::AddMiningSignaturePrivkey(DecodeSecret(privkey));
                if (IsValidDestination(dest)) {
                    LogPrintf("  Success import mining sign key for %s from `-signprivkey` \"%s\"\n", EncodeDestination(dest), strkeyLog);
                } else {
                    LogPrintf("  Fail import mining sign private key from `-signprivkey` \"%s\"\n", strkeyLog);
                }
            }
            gArgs.ForceSetArg("-signprivkey", "");
        }

    #ifdef ENABLE_WALLET
        // From current wallet
        for (auto pwallet : GetWallets()) {
            CTxDestination dest = pwallet->GetPrimaryDestination();
            CKeyID keyid = GetKeyForDestination(*pwallet, dest);
            if (!keyid.IsNull()) {
                std::shared_ptr<CKey> privKey = std::make_shared<CKey>();
                if (pwallet->GetKey(keyid, *privKey)) {
                    LOCK(cs_main);
                    mapSignaturePrivKeys[boost::get<ScriptHash>(&dest)->GetUint64(0)] = privKey;

                    LogPrintf("Import mining-sign private key from wallet primary address %s\n", EncodeDestination(dest));
                }
            }
        }
    #endif
    } else {
        LogPrintf("Skip PoC forge thread\n");
        interruptCheckDeadline();
    }

    return true;
}

void InterruptPOC()
{
    LogPrintf("Interrupting PoC module\n");
    interruptCheckDeadline();
}

void StopPOC()
{
    if (threadCheckDeadline.joinable())
        threadCheckDeadline.join();

    mapSignaturePrivKeys.clear();

    LogPrintf("Stopped PoC module\n");
}