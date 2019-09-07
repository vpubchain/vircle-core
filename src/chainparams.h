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
    std::string GetPerformanceFund() const { return strPerformanceFund; } 

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

    std::string strPerformanceFund;     //for benyuan PerformanceFund

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
    std::make_pair("1311a4687a8e46a45442e39168cd8c4e76d32344",  10 * COIN),
    std::make_pair("fb1eccc4e5846dfae0beaca5649b41111fd13e1a",  10 * COIN),
    std::make_pair("37e93da980a2aa31b41a01d5bd03654ee74e6b0a",  10 * COIN),
    std::make_pair("71e4d1c24b92724d53eaf9315cf2b345db7703f9",  10 * COIN),

    std::make_pair("1311a4687a8e46a45442e39168cd8c4e76d32344",  10 * COIN),
    std::make_pair("fb1eccc4e5846dfae0beaca5649b41111fd13e1a",  10 * COIN),
    std::make_pair("37e93da980a2aa31b41a01d5bd03654ee74e6b0a",  10 * COIN),
    std::make_pair("71e4d1c24b92724d53eaf9315cf2b345db7703f9",  10 * COIN),

    std::make_pair("1311a4687a8e46a45442e39168cd8c4e76d32344",  10 * COIN),
    std::make_pair("fb1eccc4e5846dfae0beaca5649b41111fd13e1a",  10 * COIN),
    
    //wallet-2
    std::make_pair("ffaff1eca6c46b4c761b88aed615a52d8073237e",  10 * COIN),
    std::make_pair("83da04c2a89be2d26a990509c61f5cb3295c30b3",  10 * COIN),
    std::make_pair("5f01966b5b5c4e7db612cadfed6a8ce511853e7a",  10 * COIN),
    std::make_pair("f7ff020e2cbfc646e35ee3c347dd167724a99e9c",  10 * COIN),

    std::make_pair("ffaff1eca6c46b4c761b88aed615a52d8073237e",  10 * COIN),
    std::make_pair("83da04c2a89be2d26a990509c61f5cb3295c30b3",  10 * COIN),
    std::make_pair("5f01966b5b5c4e7db612cadfed6a8ce511853e7a",  10 * COIN),
    std::make_pair("f7ff020e2cbfc646e35ee3c347dd167724a99e9c",  10 * COIN),

    std::make_pair("ffaff1eca6c46b4c761b88aed615a52d8073237e",  10 * COIN),
    std::make_pair("83da04c2a89be2d26a990509c61f5cb3295c30b3",  10 * COIN),
    
    //wallet-3
    std::make_pair("c57120065da7145d8d3fe37d5d3a9cbb248534e0",  10 * COIN),
    std::make_pair("055d4fe7b4660b2b0e452122897766f7b6192c19",  10 * COIN),
    std::make_pair("613d91ed9890cd37997f351aabb4a76748874a64",  10 * COIN),
    std::make_pair("385a6e6d96717f541b091f5761a69d900a9e20f1",  10 * COIN),

    std::make_pair("c57120065da7145d8d3fe37d5d3a9cbb248534e0",  10 * COIN),
    std::make_pair("055d4fe7b4660b2b0e452122897766f7b6192c19",  10 * COIN),
    std::make_pair("613d91ed9890cd37997f351aabb4a76748874a64",  10 * COIN),
    std::make_pair("385a6e6d96717f541b091f5761a69d900a9e20f1",  10 * COIN),

    std::make_pair("c57120065da7145d8d3fe37d5d3a9cbb248534e0",  10 * COIN),
    std::make_pair("055d4fe7b4660b2b0e452122897766f7b6192c19",  10 * COIN),

    //wallet-4
    std::make_pair("4d8fc62a72571d6976451df25a62a0375b911d7d",  10 * COIN),
    std::make_pair("4bae3b2e4bab9afc9b4eb54219543bfd8657f8cc",  10 * COIN),
    std::make_pair("3a61cd55da65b620cdaf9e630e91ba7f2a840001",  10 * COIN),
    std::make_pair("612b9cacc36a6404d24dee7ec2c5ac0942a3cfd4",  10 * COIN),

    std::make_pair("4d8fc62a72571d6976451df25a62a0375b911d7d",  10 * COIN),
    std::make_pair("4bae3b2e4bab9afc9b4eb54219543bfd8657f8cc",  10 * COIN),
    std::make_pair("3a61cd55da65b620cdaf9e630e91ba7f2a840001",  10 * COIN),
    std::make_pair("612b9cacc36a6404d24dee7ec2c5ac0942a3cfd4",  10 * COIN),

    std::make_pair("4d8fc62a72571d6976451df25a62a0375b911d7d",  10 * COIN),
    std::make_pair("4bae3b2e4bab9afc9b4eb54219543bfd8657f8cc",  10 * COIN),

    //wallet-5
    std::make_pair("01388011fa9385f24975aaae1bc91fd1c3a13455",  10 * COIN),
    std::make_pair("b71000435c6ee122b6cb7806d9d257adf0d38079",  10 * COIN),
    std::make_pair("01532a1d7f3c9b96c2a3827a33a6cc33e406983c",  10 * COIN),
    std::make_pair("4aabd40f77ed426eb9418ea7d86de78c3094edb2",  10 * COIN),

    std::make_pair("01388011fa9385f24975aaae1bc91fd1c3a13455",  10 * COIN),
    std::make_pair("b71000435c6ee122b6cb7806d9d257adf0d38079",  10 * COIN),
    std::make_pair("01532a1d7f3c9b96c2a3827a33a6cc33e406983c",  10 * COIN),
    std::make_pair("4aabd40f77ed426eb9418ea7d86de78c3094edb2",  10 * COIN),

    std::make_pair("01388011fa9385f24975aaae1bc91fd1c3a13455",  10 * COIN),
    std::make_pair("b71000435c6ee122b6cb7806d9d257adf0d38079",  10 * COIN),

    //wallet-6
    std::make_pair("4a4d3e9c519a636b55074c802d67c616f2060a73",  10 * COIN),
    std::make_pair("3eb0465c5296225e99aa9e7d370a521d67569738",  10 * COIN),
    std::make_pair("5febd672a16b0814c2676dbea96a18c523fc7e9d",  10 * COIN),
    std::make_pair("6c5e1d66e416cf857790dbe3ecd13fa4d74d5fe7",  10 * COIN),

    std::make_pair("4a4d3e9c519a636b55074c802d67c616f2060a73",  10 * COIN),
    std::make_pair("3eb0465c5296225e99aa9e7d370a521d67569738",  10 * COIN),
    std::make_pair("5febd672a16b0814c2676dbea96a18c523fc7e9d",  10 * COIN),
    std::make_pair("6c5e1d66e416cf857790dbe3ecd13fa4d74d5fe7",  10 * COIN),

    std::make_pair("4a4d3e9c519a636b55074c802d67c616f2060a73",  10 * COIN),
    std::make_pair("3eb0465c5296225e99aa9e7d370a521d67569738",  10 * COIN),

    //wallet-7
    std::make_pair("0e60bc4e2a845347cd6e2043097d36fd68838ff9",  10 * COIN),
    std::make_pair("7c4ad5ca66c800e479d39b814286d462e153aa51",  10 * COIN),
    std::make_pair("9a563d611d61bfbad451ce3b8bda308e7bafa0c1",  10 * COIN),
    std::make_pair("f0a66f4f44d0be7c38e909fd25d84cdf9f551e09",  10 * COIN),

    std::make_pair("0e60bc4e2a845347cd6e2043097d36fd68838ff9",  10 * COIN),
    std::make_pair("7c4ad5ca66c800e479d39b814286d462e153aa51",  10 * COIN),
    std::make_pair("9a563d611d61bfbad451ce3b8bda308e7bafa0c1",  10 * COIN),
    std::make_pair("f0a66f4f44d0be7c38e909fd25d84cdf9f551e09",  10 * COIN),

    std::make_pair("0e60bc4e2a845347cd6e2043097d36fd68838ff9",  10 * COIN),
    std::make_pair("7c4ad5ca66c800e479d39b814286d462e153aa51",  10 * COIN),

    //wallet-8
    std::make_pair("338adf2c410e20cb9ff7d181878d214f2eeb92a0",  10 * COIN),
    std::make_pair("042dbf19c3d8c29d42c337d21be4576d5a2d8454",  10 * COIN),
    std::make_pair("9c9e1c67d88890d5b9e81459da03529d24e2352c",  10 * COIN),
    std::make_pair("cfe70ed7a27e24e49798c033fc51e2bc9700c653",  10 * COIN),

    std::make_pair("338adf2c410e20cb9ff7d181878d214f2eeb92a0",  10 * COIN),
    std::make_pair("042dbf19c3d8c29d42c337d21be4576d5a2d8454",  10 * COIN),
    std::make_pair("9c9e1c67d88890d5b9e81459da03529d24e2352c",  10 * COIN),
    std::make_pair("cfe70ed7a27e24e49798c033fc51e2bc9700c653",  10 * COIN),

    std::make_pair("338adf2c410e20cb9ff7d181878d214f2eeb92a0",  10 * COIN),
    std::make_pair("042dbf19c3d8c29d42c337d21be4576d5a2d8454",  10 * COIN),

    //wallet-9
    std::make_pair("9e19c49700a3d25c86bdea5eefdd46fe29b16614",  10 * COIN),
    std::make_pair("70f450902c6664f88c609ba430d1ef62ff34cbdf",  10 * COIN),
    std::make_pair("f69edb89d8690b0bb9d2b1fa8fea3cb2b245b57b",  10 * COIN),
    std::make_pair("826c8371e9052571e60405723dd3002c558a2501",  10 * COIN),

    std::make_pair("9e19c49700a3d25c86bdea5eefdd46fe29b16614",  10 * COIN),
    std::make_pair("70f450902c6664f88c609ba430d1ef62ff34cbdf",  10 * COIN),
    std::make_pair("f69edb89d8690b0bb9d2b1fa8fea3cb2b245b57b",  10 * COIN),
    std::make_pair("826c8371e9052571e60405723dd3002c558a2501",  10 * COIN),

    std::make_pair("9e19c49700a3d25c86bdea5eefdd46fe29b16614",  10 * COIN),
    std::make_pair("70f450902c6664f88c609ba430d1ef62ff34cbdf",  10 * COIN),

    //wallet-10
    std::make_pair("38323271008af2e27987af604171eaac8da189f3",  10 * COIN),
    std::make_pair("f8423c86ad3991e1827f61e6da155b836058747d",  10 * COIN),
    std::make_pair("e4011d5363bd38c3c96c5a0bc2667ff41338ea00",  10 * COIN),
    std::make_pair("c6b1e373b34c7fab5e3d0771d687b0fd8f2dd616",  10 * COIN),

    std::make_pair("38323271008af2e27987af604171eaac8da189f3",  10 * COIN),
    std::make_pair("f8423c86ad3991e1827f61e6da155b836058747d",  10 * COIN),
    std::make_pair("e4011d5363bd38c3c96c5a0bc2667ff41338ea00",  10 * COIN),
    std::make_pair("c6b1e373b34c7fab5e3d0771d687b0fd8f2dd616",  10 * COIN),

    std::make_pair("38323271008af2e27987af604171eaac8da189f3",  10 * COIN),
    std::make_pair("f8423c86ad3991e1827f61e6da155b836058747d",  10 * COIN),
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
