// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <chainparamsbase.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <chain.h>
#include <protocol.h>

#include <memory>
#include <vector>

static const uint32_t CHAIN_NO_GENESIS = 444444;
static const uint32_t CHAIN_NO_STEALTH_SPEND = 444445; // used hardened

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
};

/**
 * Holds various statistics on transactions within a chain. Used to estimate
 * verification progress during chain sync.
 *
 * See also: CChainParams::TxData, GuessVerificationProgress.
 */
struct ChainTxData {
    int64_t nTime;    //!< UNIX timestamp of last known number of transactions
    int64_t nTxCount; //!< total number of transactions between genesis and that timestamp
    double dTxRate;   //!< estimated number of transactions per second after that timestamp
};

class CImportedCoinbaseTxn
{
public:
    CImportedCoinbaseTxn(uint32_t nHeightIn, uint256 hashIn) : nHeight(nHeightIn), hash(hashIn) {};
    uint32_t nHeight;
    uint256 hash; // hash of output data
};

class DevFundSettings
{
public:
    DevFundSettings(std::string sAddrTo, int nMinDevStakePercent_, int nDevOutputPeriod_)
        : sDevFundAddresses(sAddrTo), nMinDevStakePercent(nMinDevStakePercent_), nDevOutputPeriod(nDevOutputPeriod_) {};

    std::string sDevFundAddresses;
    int nMinDevStakePercent; // [0, 100]
    int nDevOutputPeriod; // dev fund output is created every n blocks
    //CAmount nMinDevOutputSize; // if nDevOutputGap is -1, create a devfund output when value is > nMinDevOutputSize
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,
        STEALTH_ADDRESS,
        EXT_KEY_HASH,
        EXT_ACC_HASH,
        EXT_PUBLIC_KEY_BTC,
        EXT_SECRET_KEY_BTC,
        PUBKEY_ADDRESS_256,
        SCRIPT_ADDRESS_256,
        STAKE_ONLY_PKADDR,
        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
    int GetDefaultPort() const { return nDefaultPort; }

    int BIP44ID() const { return nBIP44ID; }

    uint32_t GetModifierInterval() const { return nModifierInterval; }
    uint32_t GetStakeMinConfirmations() const { return nStakeMinConfirmations; }
    uint32_t GetTargetSpacing() const { return nTargetSpacing; }
    uint32_t GetTargetTimespan() const { return nTargetTimespan; }
    std::string GetPerformanceFundAddr() const { return strPerformanceFundAddr; } 

    uint32_t GetStakeTimestampMask(int nHeight) const { return nStakeTimestampMask; }
    int64_t GetCoinYearReward(int64_t nTime) const;

    const DevFundSettings *GetDevFundSettings(int64_t nTime) const;
    const std::vector<std::pair<int64_t, DevFundSettings> > &GetDevFundSettings() const {return vDevFundSettings;};

    int64_t GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const;
    int64_t GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev) const;

    bool CheckImportCoinbase(int nHeight, uint256 &hash) const;
    uint32_t GetLastImportHeight() const { return nLastImportHeight; }

    const CBlock& GenesisBlock() const { return genesis; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Minimum free space (in GB) needed for data directory */
    uint64_t AssumedBlockchainSize() const { return m_assumed_blockchain_size; }
    /** Minimum free space (in GB) needed for data directory when pruned; Does not include prune target*/
    uint64_t AssumedChainStateSize() const { return m_assumed_chain_state_size; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    /** Return true if the fallback fee is by default enabled for this network */
    bool IsFallbackFeeEnabled() const { return m_fallback_fee_enabled; }
    /** Return the list of hostnames to look up for DNS seeds */
    const std::vector<std::string>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<unsigned char>& Bech32Prefix(Base58Type type) const { return bech32Prefixes[type]; }
    const std::string& Bech32HRP() const { return bech32_hrp; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
    const ChainTxData& TxData() const { return chainTxData; }

    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const;
    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const;
    bool IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const;

    std::string NetworkID() const { return strNetworkID; }

    void SetCoinYearReward(int64_t nCoinYearReward_)
    {
        assert(strNetworkID == "regtest");
        nCoinYearReward = nCoinYearReward_;
    }

protected:
    CChainParams() {}

    void SetLastImportHeight()
    {
        nLastImportHeight = 0;
        for (auto cth : vImportedCoinbaseTxns) {
            nLastImportHeight = std::max(nLastImportHeight, cth.nHeight);
        }
    }

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    int nDefaultPort;
    int nBIP44ID;

    uint32_t nModifierInterval;         // seconds to elapse before new modifier is computed
    uint32_t nStakeMinConfirmations;    // min depth in chain before staked output is spendable
    uint32_t nTargetSpacing;            // targeted number of seconds between blocks
    uint32_t nTargetTimespan;

    std::string strPerformanceFundAddr;     //for benyuan PerformanceFund

    uint32_t nStakeTimestampMask = (1 << 4) -1; // 4 bits, every kernel stake hash will change every 16 seconds
    int64_t nCoinYearReward = 2 * CENT; // 2% per year

    std::vector<CImportedCoinbaseTxn> vImportedCoinbaseTxns;
    uint32_t nLastImportHeight;       // set from vImportedCoinbaseTxns

    std::vector<std::pair<int64_t, DevFundSettings> > vDevFundSettings;


    uint64_t nPruneAfterHeight;
    uint64_t m_assumed_blockchain_size;
    uint64_t m_assumed_chain_state_size;
    std::vector<std::string> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::vector<unsigned char> bech32Prefixes[MAX_BASE58_TYPES];
    std::string bech32_hrp;
    std::string strNetworkID;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    CCheckpointData checkpointData;
    ChainTxData chainTxData;
    bool m_fallback_fee_enabled;
};

/**
 * Creates and returns a std::unique_ptr<CChainParams> of the chosen chain.
 * @returns a CChainParams* of the chosen chain.
 * @throws a std::runtime_error if the chain is not supported.
 */
std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();
const CChainParams *pParams();

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

/**
 * Toggle old parameters for unit tests
 */
void SetOldParams(std::unique_ptr<CChainParams> &params);
void ResetParams(std::string sNetworkId, bool fVircleModeIn);

/**
 * mutable handle to regtest params
 */
CChainParams &RegtestParams();

const std::pair<const char*, CAmount> regTestOutputs[] = {
    std::make_pair("afe7c881db847cd23db8444769d900d8677d7e1b",  10000 * COIN),
    std::make_pair("b77eeb6b23695314bacd1897edf7b08c6570d0cd",  10000 * COIN),
    std::make_pair("7811f9c09f63700d15462243a32b13e5ac54287",   10000 * COIN),
    std::make_pair("65c3e5f22f3984ec4967f35f895c288fcaf95c31",  10000 * COIN),

    std::make_pair("4764b46a4d06feae1a7029161df54413fb8a9daf",  5000 * COIN),
    std::make_pair("7a5256b27cce221deec4aafcee866d1e2282d96",   5000 * COIN),
    std::make_pair("eb528574c134b053eb4cbc2e19a4825dc24e656a",  5000 * COIN),
    std::make_pair("68e28519bff057f63819abe6b90050d1b17adddb",  5000 * COIN),
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {       
    //wallet-1
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),

    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    std::make_pair("bd9e3a4031bfaed4e203787db77b085ba55daca1",  10 * COIN),
    
    //wallet-2
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),

    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    std::make_pair("dd51ab8cc63df25f9f5b52d3bda1f9995815a898",  10 * COIN),
    
    //wallet-3
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),

    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),
    std::make_pair("815859f4c5ca63cbf427515dbfccf24f916a39c4",  10 * COIN),

    //wallet-4
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),
    std::make_pair("cd1cf6bc6679efacf03a6254739fb866fe2f4211",  10 * COIN),

    //wallet-5
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),

    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),
    std::make_pair("1d513773032ceeab8cb5991790839d12d4725ecf",  10 * COIN),

    //wallet-6
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),

    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),
    std::make_pair("b6588dabda3bb8a589fa30ddaf0c6c3a7e369551",  10 * COIN),

    //wallet-7
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),

    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),
    std::make_pair("cd9ce8303a41b420ba54cdfc2981e26b01ec3664",  10 * COIN),

    //wallet-8
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),

    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),
    std::make_pair("083d3a0e823b7688dc63a5f88b414f0ffef2c6cb",  10 * COIN),

    //wallet-9
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),

    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),
    std::make_pair("c261ea9f7df3b51802ee37fe374544790262988a",  10 * COIN),

    //wallet-10
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),

    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),
    std::make_pair("034747bae24548abcdb5849d620999a7767c8562",  10 * COIN),

};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
    std::make_pair("da708d4837449773b2b992bcf632c3e5ede4b816",200000    * COIN),
    std::make_pair("33626525f092614ffeba7184f59d377233606512",200000    * COIN),
    std::make_pair("bff5c2122f1b15e81813264ef682f162e06570fc",200000    * COIN),
    std::make_pair("81cf20dc7588356340f9cb9350a75454db2be90e",200000    * COIN),
    std::make_pair("b018a97c518613f7075bb23809c20fb891097e2c",200000    * COIN),

    std::make_pair("69345d6be457b994627cf9ad5190c91459977f60",200000    * COIN),
    std::make_pair("6376a3489d220a0db00c0d734c73ab167558d07f",200000    * COIN),
    std::make_pair("05eb66e0d695a632900934942ab77643a9c5f660",200000     * COIN),
    std::make_pair("04a6eb77602392ed79958be78ef9632f82cb124a",200000    * COIN),
    std::make_pair("c43453cf155302598e3d15476664eb7e0d4e67c6",200000     * COIN),
    
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);

#endif // BITCOIN_CHAINPARAMS_H
