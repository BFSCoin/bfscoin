// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint64_t nBaseTarget;
    uint64_t nNonce;
    uint64_t nPlotterId;
    uint64_t nPledgeCapacity;
    // block signature by generator
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSignature;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // Read: Signature flag and base target read from stream. Real base target require remove mask
        // Write: Signature flag and base target write to stream
        uint64_t nFlags = nBaseTarget | (vchPubKey.empty() ? 0 : 0x8000000000000000L);
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nFlags);
        READWRITE(nNonce);
        READWRITE(nPlotterId);
        READWRITE(nPledgeCapacity);
        nBaseTarget = nFlags & 0x7fffffffffffffffL;
        if (nFlags & 0x8000000000000000L) {
            READWRITE(LIMITED_VECTOR(vchPubKey, CPubKey::COMPRESSED_PUBLIC_KEY_SIZE));
            // Signature block data exclude vchSignature
            if (!(GetSerializeType(s) & SER_UNSIGNATURED)) {
                READWRITE(LIMITED_VECTOR(vchSignature, CPubKey::SIGNATURE_SIZE));
            }
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBaseTarget = 0;
        nNonce = 0;
        nPlotterId = 0;
        nPledgeCapacity = 0;
        vchPubKey.clear();
        vchSignature.clear();
    }

    bool IsNull() const
    {
        return (nBaseTarget == 0);
    }

    uint256 GetHash() const;
    uint256 GetUnsignaturedHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBaseTarget    = nBaseTarget;
        block.nNonce         = nNonce;
        block.nPlotterId     = nPlotterId;
        block.nPledgeCapacity = nPledgeCapacity;
        block.vchPubKey      = vchPubKey;
        block.vchSignature   = vchSignature;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
