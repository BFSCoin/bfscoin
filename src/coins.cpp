// Copyright (c) 2012-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <logging.h>
#include <pubkey.h>
#include <random.h>
#include <script/script.h>
#include <version.h>

bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return false; }
CCoinsViewCursorRef CCoinsView::Cursor() const { return nullptr; }
CCoinsViewCursorRef CCoinsView::Cursor(const CAccountID &accountID) const { return nullptr; }
CCoinsViewCursorRef CCoinsView::PointSendCursor(const CAccountID &accountID) const { return nullptr; }
CCoinsViewCursorRef CCoinsView::PointReceiveCursor(const CAccountID &accountID) const { return nullptr; }
CAmount CCoinsView::GetBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins,
        CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive) const {
    if (balanceBindPlotter != nullptr) *balanceBindPlotter = 0;
    if (balancePointSend != nullptr) *balancePointSend = 0;
    if (balancePointReceive != nullptr) *balancePointReceive = 0;
    return 0;
}
CBindPlotterCoinsMap CCoinsView::GetAccountBindPlotterEntries(const CAccountID &accountID, const uint64_t &plotterId) const { return {}; }
CBindPlotterCoinsMap CCoinsView::GetBindPlotterEntries(const uint64_t &plotterId) const { return {}; }
bool CCoinsView::HaveCoin(const COutPoint &outpoint) const {
    Coin coin;
    return GetCoin(outpoint, coin);
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return base->BatchWrite(mapCoins, hashBlock); }
CCoinsViewCursorRef CCoinsViewBacked::Cursor() const { return base->Cursor(); }
CCoinsViewCursorRef CCoinsViewBacked::Cursor(const CAccountID &accountID) const { return base->Cursor(accountID); }
CCoinsViewCursorRef CCoinsViewBacked::PointSendCursor(const CAccountID &accountID) const { return base->PointSendCursor(accountID); }
CCoinsViewCursorRef CCoinsViewBacked::PointReceiveCursor(const CAccountID &accountID) const { return base->PointReceiveCursor(accountID); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }
CAmount CCoinsViewBacked::GetBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive) const {
    return base->GetBalance(accountID, mapChildCoins, balanceBindPlotter, balancePointSend, balancePointReceive);
}
CBindPlotterCoinsMap CCoinsViewBacked::GetAccountBindPlotterEntries(const CAccountID &accountID, const uint64_t &plotterId) const {
    return base->GetAccountBindPlotterEntries(accountID, plotterId);
}
CBindPlotterCoinsMap CCoinsViewBacked::GetBindPlotterEntries(const uint64_t &plotterId) const {
    return base->GetBindPlotterEntries(plotterId);
}

SaltedOutpointHasher::SaltedOutpointHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), cachedCoinsUsage(0) {}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
        return it;
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();
    CCoinsMap::iterator ret = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp))).first;
    if (ret->second.coin.IsSpent()) {
        assert(false); // GetCoin() only return unspent coin
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it != cacheCoins.end()) {
        coin = it->second.coin;
        return !coin.IsSpent();
    }
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    if (fresh && it->second.coin.IsBindPlotter())
        fresh = false;
    it->second.coin = std::move(coin);
    it->second.coin.Refresh();
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    it->second.flags &= ~CCoinsCacheEntry::UNBIND;
    if (it->second.coin.IsBindPlotter())
        it->second.flags &= ~CCoinsCacheEntry::FRESH;
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check) {
    // Parse special transaction
    CDatacarrierPayloadRef extraData;
    if (nHeight >= Params().GetConsensus().BFSIP002Height)
        extraData = ExtractTransactionDatacarrier(tx, nHeight, DatacarrierTypes{DATACARRIER_TYPE_BINDPLOTTER, DATACARRIER_TYPE_POINT});

    // Add coin
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Always set the possible_overwrite flag to AddCoin for coinbase txn, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.

        Coin coin(tx.vout[i], nHeight, fCoinbase);
        // Set extra data to coin of vout[0]
        if (i == 0 && extraData)
            coin.extraData = std::move(extraData);
        cache.AddCoin(COutPoint(txid, i), std::move(coin), overwrite);
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout, bool rollback) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end())
        return false;

    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    if (moveout)
        *moveout = it->second.coin;

    if (!rollback && it->second.coin.IsBindPlotter() && it->second.coin.nHeight >= Params().GetConsensus().BFSIP002LimitBindPlotterHeight) {
        it->second.flags |= CCoinsCacheEntry::DIRTY | CCoinsCacheEntry::UNBIND;
        it->second.flags &= ~CCoinsCacheEntry::FRESH;
        it->second.coin.Clear();
    } else if (it->second.flags & CCoinsCacheEntry::FRESH) {
        cacheCoins.erase(it);
    } else {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.flags &= ~CCoinsCacheEntry::UNBIND;
        if (it->second.coin.IsBindPlotter())
            it->second.flags &= ~CCoinsCacheEntry::FRESH;
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlockIn) {
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end(); it = mapCoins.erase(it)) {
        // Ignore non-dirty entries (optimization).
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child does
            // We can ignore it if it's both FRESH and pruned in the child
            if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                // Otherwise we will need to create it in the parent
                // and move the data up and mark it as dirty
                CCoinsCacheEntry& entry = cacheCoins[it->first];
                entry.coin = std::move(it->second.coin);
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                entry.flags = CCoinsCacheEntry::DIRTY;
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.flags & CCoinsCacheEntry::FRESH) {
                    assert(!entry.coin.IsBindPlotter());
                    entry.flags |= CCoinsCacheEntry::FRESH;
                }
                // Sync UNBIND from child
                if (it->second.flags & CCoinsCacheEntry::UNBIND) {
                    assert(entry.coin.IsSpent());
                    entry.flags |= CCoinsCacheEntry::UNBIND;
                }
                if (LogAcceptCategory(BCLog::COINDB))
                    LogPrintf("%s: <%s,%3u> (height=%u spent=%d flags=%08x type=%08x) <Add new>\n", __func__,
                        it->first.hash.ToString(), it->first.n,
                        entry.coin.nHeight, entry.coin.IsSpent() ? 1 : 0, entry.flags, entry.coin.extraData ? entry.coin.extraData->type : 0);
            } else {
                if (LogAcceptCategory(BCLog::COINDB))
                    LogPrintf("%s: <%s,%3u> (height=%u spent=%d flags=%08x type=%08x) <Discard>\n", __func__,
                        it->first.hash.ToString(), it->first.n,
                        it->second.coin.nHeight, it->second.coin.IsSpent() ? 1 : 0, it->second.flags, it->second.coin.extraData ? it->second.coin.extraData->type : 0);
            }
        } else {
            // Assert that the child cache entry was not marked FRESH if the
            // parent cache entry has unspent outputs. If this ever happens,
            // it means the FRESH flag was misapplied and there is a logic
            // error in the calling code.
            if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
            }

            // Found the entry in the parent cache
            if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent() && !it->second.coin.IsBindPlotter()) {
                if (LogAcceptCategory(BCLog::COINDB))
                    LogPrintf("%s: <%s,%3u> (height=%u spent=%d flags=%08x type=%08x) => (height=%u spent=%d flags=%08x type=%08x) <Discard>\n", __func__,
                        it->first.hash.ToString(), it->first.n,
                        it->second.coin.nHeight, it->second.coin.IsSpent() ? 1 : 0, it->second.flags, it->second.coin.extraData ? it->second.coin.extraData->type : 0,
                        itUs->second.coin.nHeight, itUs->second.coin.IsSpent() ? 1 : 0, itUs->second.flags, itUs->second.coin.extraData ? itUs->second.coin.extraData->type : 0);
                // The grandparent does not have an entry, and the child is
                // modified and being pruned. This means we can just delete
                // it from the parent.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
                if (LogAcceptCategory(BCLog::COINDB))
                    LogPrintf("%s: <%s,%3u> (height=%u spent=%d flags=%08x type=%08x) => (height=%u spent=%d flags=%08x type=%08x) <Merge>\n", __func__,
                        it->first.hash.ToString(), it->first.n,
                        it->second.coin.nHeight, it->second.coin.IsSpent() ? 1 : 0, it->second.flags, it->second.coin.extraData ? it->second.coin.extraData->type : 0,
                        itUs->second.coin.nHeight, itUs->second.coin.IsSpent() ? 1 : 0, itUs->second.flags, itUs->second.coin.extraData ? itUs->second.coin.extraData->type : 0);
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                itUs->second.coin = std::move(it->second.coin);
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                itUs->second.flags &= ~CCoinsCacheEntry::UNBIND;
                if (itUs->second.coin.IsBindPlotter()) {
                    itUs->second.flags &= ~CCoinsCacheEntry::FRESH;
                }
                // Sync UNBIND from child
                if (it->second.flags & CCoinsCacheEntry::UNBIND) {
                    assert(itUs->second.coin.IsSpent());
                    itUs->second.flags |= CCoinsCacheEntry::UNBIND;
                }
                // NOTE: It is possible the child has a FRESH flag here in
                // the event the entry we found in the parent is pruned. But
                // we must not copy that FRESH flag to the parent as that
                // pruned state likely still needs to be communicated to the
                // grandparent.
            }
        }
    }
    hashBlock = hashBlockIn;
    return true;
}

CAmount CCoinsViewCache::GetBalance(const CAccountID &accountID, const CCoinsMap &mapChildCoins, CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive) const {
    if (cacheCoins.empty()) {
        return base->GetBalance(accountID, mapChildCoins, balanceBindPlotter, balancePointSend, balancePointReceive);
    } else if (mapChildCoins.empty()) {
        return base->GetBalance(accountID, cacheCoins, balanceBindPlotter, balancePointSend, balancePointReceive);
    } else {
        CCoinsMap mapCoinsMerged;
        // Copy mine relative coins
        for (CCoinsMap::const_iterator it = cacheCoins.cbegin(); it != cacheCoins.cend(); it++) {
            if (it->second.coin.refOutAccountID != accountID &&
                (!it->second.coin.IsPoint() || PointPayload::As(it->second.coin.extraData)->GetReceiverID() != accountID)) {
                // NOT mine and NOT debit to me
                continue;
            }
            mapCoinsMerged[it->first] = it->second;
        }
        if (mapCoinsMerged.empty()) {
            return base->GetBalance(accountID, mapChildCoins, balanceBindPlotter, balancePointSend, balancePointReceive);
        } else {
            // Merge child and mine coins
            // See CCoinsViewCache::BatchWrite()
            for (CCoinsMap::const_iterator it = mapChildCoins.cbegin(); it != mapChildCoins.cend(); it++) {
                if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
                    continue;
                }
                if (it->second.coin.refOutAccountID != accountID &&
                    (!it->second.coin.IsPoint() || PointPayload::As(it->second.coin.extraData)->GetReceiverID() != accountID)) {
                    // NOT mine and NOT debit to me
                    continue;
                }
                CCoinsMap::iterator itUs = mapCoinsMerged.find(it->first);
                if (itUs == mapCoinsMerged.end()) {
                    if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                        CCoinsCacheEntry& entry = mapCoinsMerged[it->first];
                        entry.coin = it->second.coin;
                        entry.flags = CCoinsCacheEntry::DIRTY;
                        if (it->second.flags & CCoinsCacheEntry::FRESH) {
                            assert(!entry.coin.IsBindPlotter());
                            entry.flags |= CCoinsCacheEntry::FRESH;
                        }
                        if (it->second.flags & CCoinsCacheEntry::UNBIND) {
                            assert(entry.coin.IsSpent());
                            entry.flags |= CCoinsCacheEntry::UNBIND;
                        }
                    }
                } else {
                    if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                        throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
                    }
                    if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent() && !it->second.coin.IsBindPlotter()) {
                        mapCoinsMerged.erase(itUs);
                    } else {
                        itUs->second.coin = it->second.coin;
                        itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                        itUs->second.flags &= ~CCoinsCacheEntry::UNBIND;
                        if (itUs->second.coin.IsBindPlotter()) {
                            itUs->second.flags &= ~CCoinsCacheEntry::FRESH;
                        }
                        if (it->second.flags & CCoinsCacheEntry::UNBIND) {
                            assert(itUs->second.coin.IsSpent());
                            itUs->second.flags |= CCoinsCacheEntry::UNBIND;
                        }
                    }
                }
            }
            return base->GetBalance(accountID, mapCoinsMerged, balanceBindPlotter, balancePointSend, balancePointReceive);
        }
    }
}

CBindPlotterCoinsMap CCoinsViewCache::GetAccountBindPlotterEntries(const CAccountID &accountID, const uint64_t &plotterId) const {
    // From base view
    CBindPlotterCoinsMap outpoints = base->GetAccountBindPlotterEntries(accountID, plotterId);

    // Apply modified
    for (CCoinsMap::iterator it = cacheCoins.begin(); it != cacheCoins.end(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY))
            continue;

        if (accountID != it->second.coin.refOutAccountID) {
            outpoints.erase(it->first);
            continue;
        }

        auto itSelected = outpoints.find(it->first);
        if (itSelected != outpoints.end()) {
            if (it->second.coin.IsSpent() && !(it->second.flags & CCoinsCacheEntry::UNBIND)) {
                outpoints.erase(itSelected);
            } else if (it->second.coin.IsBindPlotter()) {
                if (plotterId == 0 || plotterId == BindPlotterPayload::As(it->second.coin.extraData)->GetId()) {
                    itSelected->second.nHeight = it->second.coin.nHeight;
                    itSelected->second.accountID = it->second.coin.refOutAccountID;
                    itSelected->second.plotterId = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                    itSelected->second.valid = !it->second.coin.IsSpent();
                } else {
                    outpoints.erase(itSelected);
                }
            } else {
                outpoints.erase(itSelected);
            }
        } else {
            if (it->second.coin.IsBindPlotter() && (plotterId == 0 || plotterId == BindPlotterPayload::As(it->second.coin.extraData)->GetId())) {
                if (!it->second.coin.IsSpent() || (it->second.flags & CCoinsCacheEntry::UNBIND)) {
                    CBindPlotterCoinInfo &info = outpoints[it->first];
                    info.nHeight = it->second.coin.nHeight;
                    info.accountID = it->second.coin.refOutAccountID;
                    info.plotterId = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                    info.valid = !it->second.coin.IsSpent();
                }
            }
        }
    }

    return outpoints;
}

CBindPlotterCoinsMap CCoinsViewCache::GetBindPlotterEntries(const uint64_t &plotterId) const {
    // From base view
    CBindPlotterCoinsMap outpoints = base->GetBindPlotterEntries(plotterId);

    // Apply modified
    for (CCoinsMap::iterator it = cacheCoins.begin(); it != cacheCoins.end(); it++) {
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY))
            continue;

        auto itSelected = outpoints.find(it->first);
        if (itSelected != outpoints.end()) {
            if (it->second.coin.IsSpent() && !(it->second.flags & CCoinsCacheEntry::UNBIND)) {
                outpoints.erase(itSelected);
            } else if (it->second.coin.IsBindPlotter()) {
                if (plotterId == BindPlotterPayload::As(it->second.coin.extraData)->GetId()) {
                    itSelected->second.nHeight = it->second.coin.nHeight;
                    itSelected->second.accountID = it->second.coin.refOutAccountID;
                    itSelected->second.plotterId = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                    itSelected->second.valid = !it->second.coin.IsSpent();
                } else {
                    outpoints.erase(itSelected);
                }
            } else {
                outpoints.erase(itSelected);
            }
        } else {
            if (it->second.coin.IsBindPlotter() && plotterId == BindPlotterPayload::As(it->second.coin.extraData)->GetId()) {
                if (!it->second.coin.IsSpent() || (it->second.flags & CCoinsCacheEntry::UNBIND)) {
                    CBindPlotterCoinInfo &info = outpoints[it->first];
                    info.nHeight = it->second.coin.nHeight;
                    info.accountID = it->second.coin.refOutAccountID;
                    info.plotterId = BindPlotterPayload::As(it->second.coin.extraData)->GetId();
                    info.valid = !it->second.coin.IsSpent();
                }
            }
        }
    }

    return outpoints;
}

CAmount CCoinsViewCache::GetAccountBalance(const CAccountID &accountID, CAmount *balanceBindPlotter, CAmount *balancePointSend, CAmount *balancePointReceive) const {
    // Merge to parent
    return base->GetBalance(accountID, cacheCoins, balanceBindPlotter, balancePointSend, balancePointReceive);
}

CBindPlotterInfo CCoinsViewCache::GetChangeBindPlotterInfo(const CBindPlotterInfo &sourceBindInfo, bool compatible) const {
    assert(!sourceBindInfo.outpoint.IsNull());

    CBindPlotterInfo changeBindInfo;
    if (compatible) {
        // Compatible BFSIP002 before. Use last active coin
        for (const auto& pair : GetBindPlotterEntries(sourceBindInfo.plotterId)) {
            if (!pair.second.valid ||
                    (pair.first == sourceBindInfo.outpoint) ||
                    (pair.second.nHeight < sourceBindInfo.nHeight) ||
                    (pair.second.nHeight == sourceBindInfo.nHeight && pair.first < sourceBindInfo.outpoint))
                continue;

            // Select smallest bind
            if (changeBindInfo.nHeight < pair.second.nHeight ||
                    (changeBindInfo.nHeight == pair.second.nHeight && changeBindInfo.outpoint < pair.first))
                changeBindInfo = CBindPlotterInfo(pair);
        }
    } else {
        changeBindInfo.nHeight = 0x7fffffff;
        for (const auto& pair : GetBindPlotterEntries(sourceBindInfo.plotterId)) {
            if ((pair.first == sourceBindInfo.outpoint) ||
                    (pair.second.nHeight < sourceBindInfo.nHeight) ||
                    (pair.second.nHeight == sourceBindInfo.nHeight && pair.first < sourceBindInfo.outpoint))
                continue;

            // Select smallest bind
            if (changeBindInfo.nHeight > pair.second.nHeight ||
                    (changeBindInfo.nHeight == pair.second.nHeight && pair.first < changeBindInfo.outpoint))
                changeBindInfo = CBindPlotterInfo(pair);
        }
    }
    return changeBindInfo.outpoint.IsNull() ? sourceBindInfo : changeBindInfo;
}

CBindPlotterInfo CCoinsViewCache::GetLastBindPlotterInfo(const uint64_t &plotterId) const {
    CBindPlotterInfo lastBindInfo;
    for (const auto& pair : GetBindPlotterEntries(plotterId)) {
        assert(pair.second.plotterId == plotterId);
        if (lastBindInfo.outpoint.IsNull() ||
                (lastBindInfo.nHeight < pair.second.nHeight) ||
                (lastBindInfo.nHeight == pair.second.nHeight && lastBindInfo.outpoint < pair.first))
            lastBindInfo = CBindPlotterInfo(pair);
    }
    return lastBindInfo;
}

const Coin& CCoinsViewCache::GetLastBindPlotterCoin(const uint64_t &plotterId, COutPoint *outpoint) const {
    CBindPlotterInfo lastBindInfo = GetLastBindPlotterInfo(plotterId);
    if (outpoint) *outpoint = lastBindInfo.outpoint;
    if (!lastBindInfo.valid)
        return coinEmpty;

    const Coin& coin = AccessCoin(lastBindInfo.outpoint);
    assert(!coin.IsSpent());
    assert(coin.IsBindPlotter());
    assert(BindPlotterPayload::As(coin.extraData)->GetId() == plotterId);
    return coin;
}

bool CCoinsViewCache::HaveActiveBindPlotter(const CAccountID &accountID, const uint64_t &plotterId) const {
    CBindPlotterInfo lastBindInfo = GetLastBindPlotterInfo(plotterId);
    return lastBindInfo.valid && lastBindInfo.accountID == accountID;
}

std::set<uint64_t> CCoinsViewCache::GetAccountBindPlotters(const CAccountID &accountID) const {
    std::set<uint64_t> plotters;
    for (const auto& pair: GetAccountBindPlotterEntries(accountID)) {
        if (pair.second.valid)
            plotters.insert(pair.second.plotterId);
    }
    return plotters;
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, hashBlock);
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

CAmount CCoinsViewCache::GetValueIn(const CTransaction& tx) const
{
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        nResult += AccessCoin(tx.vin[i].prevout).out.nValue;

    return nResult;
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut(), PROTOCOL_VERSION);
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const uint256& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}

bool CCoinsViewErrorCatcher::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    try {
        return CCoinsViewBacked::GetCoin(outpoint, coin);
    } catch(const std::runtime_error& e) {
        for (auto f : m_err_callbacks) {
            f();
        }
        LogPrintf("Error reading from database: %s\n", e.what());
        // Starting the shutdown sequence and returning false to the caller would be
        // interpreted as 'entry not found' (as opposed to unable to read data), and
        // could lead to invalid interpretation. Just exit immediately, as we can't
        // continue anyway, and all writes should be atomic.
        std::abort();
    }
}
