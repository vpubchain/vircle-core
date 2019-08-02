// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <versionbitsinfo.h>

#include <chainparamsimport.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

int64_t CChainParams::GetCoinYearReward(int64_t nTime) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    if (strNetworkID != "regtest") {
        // Y1 5%, Y2 4%, Y3 3%, Y4 2%, ... YN 2%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis >= 0 && nYearsSinceGenesis < 3) {
            return (5 - nYearsSinceGenesis) * CENT;
        }
    }

    return nCoinYearReward;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    // int64_t nSubsidy;
    // // 1~1440 block reward =0 : lkz 2019-5-11
    // if (pindexPrev->nHeight >= 0 && pindexPrev->nHeight <= 1440){
    //     nSubsidy = 0 ;
    // } else {
    //    nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));
    // }
    
    // // nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));
    // return nSubsidy + nFees;


    //for benyuan
    int halvings = pindexPrev->nHeight / consensus.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 76 * COIN;
    // Subsidy is cut in half every 525,600 blocks which will occur approximately every 1 years.
    nSubsidy >>= halvings;
    return nSubsidy + nFees;
};

int64_t CChainParams::GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev) const
{
     return (smsg_fee_prev * consensus.smsg_fee_max_delta_percent) / 1000000;
};

bool CChainParams::CheckImportCoinbase(int nHeight, uint256 &hash) const
{
    for (auto &cth : Params().vImportedCoinbaseTxns) {
        if (cth.nHeight != (uint32_t)nHeight) {
            continue;
        }
        if (hash == cth.hash) {
            return true;
        }
        return error("%s - Hash mismatch at height %d: %s, expect %s.", __func__, nHeight, hash.ToString(), cth.hash.ToString());
    }

    return error("%s - Unknown height.", __func__);
};


const DevFundSettings *CChainParams::GetDevFundSettings(int64_t nTime) const
{
    for (auto i = vDevFundSettings.rbegin(); i != vDevFundSettings.rend(); ++i) {
        if (nTime > i->first) {
            return &i->second;
        }
    }

    return nullptr;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)  {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        const auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
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
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
    std::make_pair("afe7c881db847cd23db8444769d900d8677d7e1b", 10000 * COIN),
    std::make_pair("b77eeb6b23695314bacd1897edf7b08c6570d0cd", 10000 * COIN),
    std::make_pair("7811f9c09f63700d15462243a32b13e5ac54287", 10000 * COIN),
    std::make_pair("65c3e5f22f3984ec4967f35f895c288fcaf95c31", 10000 * COIN),

    std::make_pair("4764b46a4d06feae1a7029161df54413fb8a9daf", 5000 * COIN),
    std::make_pair("7a5256b27cce221deec4aafcee866d1e2282d96", 5000 * COIN),
    std::make_pair("eb528574c134b053eb4cbc2e19a4825dc24e656a", 5000 * COIN),
    std::make_pair("68e28519bff057f63819abe6b90050d1b17adddb", 5000 * COIN),
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {       
    //wallet-1
    std::make_pair("1311a4687a8e46a45442e39168cd8c4e76d32344",20000    * COIN),
    std::make_pair("fb1eccc4e5846dfae0beaca5649b41111fd13e1a",20000    * COIN),
    std::make_pair("37e93da980a2aa31b41a01d5bd03654ee74e6b0a",20000    * COIN),
    std::make_pair("71e4d1c24b92724d53eaf9315cf2b345db7703f9",20000    * COIN),
    std::make_pair("6fb2706da4e84cf3ab81f39647a4389be29dee42",20000    * COIN),

    std::make_pair("1311a4687a8e46a45442e39168cd8c4e76d32344",20000    * COIN),
    std::make_pair("fb1eccc4e5846dfae0beaca5649b41111fd13e1a",20000    * COIN),
    std::make_pair("37e93da980a2aa31b41a01d5bd03654ee74e6b0a",20000    * COIN),
    std::make_pair("71e4d1c24b92724d53eaf9315cf2b345db7703f9",20000    * COIN),
    std::make_pair("6fb2706da4e84cf3ab81f39647a4389be29dee42",20000    * COIN),
    
    //wallet-2
    std::make_pair("ffaff1eca6c46b4c761b88aed615a52d8073237e",20000    * COIN),
    std::make_pair("83da04c2a89be2d26a990509c61f5cb3295c30b3",20000    * COIN),
    std::make_pair("5f01966b5b5c4e7db612cadfed6a8ce511853e7a",20000    * COIN),
    std::make_pair("f7ff020e2cbfc646e35ee3c347dd167724a99e9c",20000    * COIN),
    std::make_pair("b0f935e4dba5f2c58b1c27bb7be60bfe1de2de24",20000    * COIN),
    
    std::make_pair("ffaff1eca6c46b4c761b88aed615a52d8073237e",20000    * COIN),
    std::make_pair("83da04c2a89be2d26a990509c61f5cb3295c30b3",20000    * COIN),
    std::make_pair("5f01966b5b5c4e7db612cadfed6a8ce511853e7a",20000    * COIN),
    std::make_pair("f7ff020e2cbfc646e35ee3c347dd167724a99e9c",20000    * COIN),
    std::make_pair("b0f935e4dba5f2c58b1c27bb7be60bfe1de2de24",20000    * COIN),

    //wallet-3
    std::make_pair("c57120065da7145d8d3fe37d5d3a9cbb248534e0",20000    * COIN),
    std::make_pair("055d4fe7b4660b2b0e452122897766f7b6192c19",20000    * COIN),
    std::make_pair("613d91ed9890cd37997f351aabb4a76748874a64",20000    * COIN),
    std::make_pair("385a6e6d96717f541b091f5761a69d900a9e20f1",20000    * COIN),
    std::make_pair("d0b3536a296c7ffb83c62fe7b86e931c69e5fd4e",20000    * COIN),

    std::make_pair("c57120065da7145d8d3fe37d5d3a9cbb248534e0",20000    * COIN),
    std::make_pair("055d4fe7b4660b2b0e452122897766f7b6192c19",20000    * COIN),
    std::make_pair("613d91ed9890cd37997f351aabb4a76748874a64",20000    * COIN),
    std::make_pair("385a6e6d96717f541b091f5761a69d900a9e20f1",20000    * COIN),
    std::make_pair("d0b3536a296c7ffb83c62fe7b86e931c69e5fd4e",20000    * COIN),

    //wallet-4
    std::make_pair("4d8fc62a72571d6976451df25a62a0375b911d7d",20000    * COIN),
    std::make_pair("4bae3b2e4bab9afc9b4eb54219543bfd8657f8cc",20000    * COIN),
    std::make_pair("3a61cd55da65b620cdaf9e630e91ba7f2a840001",20000    * COIN),
    std::make_pair("612b9cacc36a6404d24dee7ec2c5ac0942a3cfd4",20000    * COIN),
    std::make_pair("c8ab8421d67135723a5276557c2003ce8fbcf1d8",20000    * COIN),

    std::make_pair("4d8fc62a72571d6976451df25a62a0375b911d7d",20000    * COIN),
    std::make_pair("4bae3b2e4bab9afc9b4eb54219543bfd8657f8cc",20000    * COIN),
    std::make_pair("3a61cd55da65b620cdaf9e630e91ba7f2a840001",20000    * COIN),
    std::make_pair("612b9cacc36a6404d24dee7ec2c5ac0942a3cfd4",20000    * COIN),
    std::make_pair("c8ab8421d67135723a5276557c2003ce8fbcf1d8",20000    * COIN),

    //wallet-5
    std::make_pair("01388011fa9385f24975aaae1bc91fd1c3a13455",20000    * COIN),
    std::make_pair("b71000435c6ee122b6cb7806d9d257adf0d38079",20000    * COIN),
    std::make_pair("01532a1d7f3c9b96c2a3827a33a6cc33e406983c",20000    * COIN),
    std::make_pair("4aabd40f77ed426eb9418ea7d86de78c3094edb2",20000    * COIN),
    std::make_pair("16d286a0b0a5a7a14a282487f3ef07fbaab063cb",20000    * COIN),

    std::make_pair("01388011fa9385f24975aaae1bc91fd1c3a13455",20000    * COIN),
    std::make_pair("b71000435c6ee122b6cb7806d9d257adf0d38079",20000    * COIN),
    std::make_pair("01532a1d7f3c9b96c2a3827a33a6cc33e406983c",20000    * COIN),
    std::make_pair("4aabd40f77ed426eb9418ea7d86de78c3094edb2",20000    * COIN),
    std::make_pair("16d286a0b0a5a7a14a282487f3ef07fbaab063cb",20000    * COIN),
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


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 16:00:02 17/04/2019 created by jiuling vpubchain";

    CMutableTransaction txNew;
    txNew.nVersion = VIRCLE_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsRegtest);
    for (size_t k = 0; k < nGenesisOutputsRegtest; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = regTestOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(regTestOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VIRCLE_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "More pragmatism and rationality needed for China-U.S. trade talk";

    CMutableTransaction txNew;
    txNew.nVersion = VIRCLE_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsTestnet);
    for (size_t k = 0; k < nGenesisOutputsTestnet; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputsTestnet[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputsTestnet[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    // rNMepWLgH59GEdx5yZfArjkTwYLrNqnXhJ
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 150000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("b0d8020986e7d6c4873295ecaf6d53d00136253d") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative 2 
    // rScS9ymKzA4t9Ftg6jyeeoYFz8TyBcTapr
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 200000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("df842dce26c76df7fee7a39f471858779b7ea871") << OP_EQUAL;
    txNew.vpout.push_back(out);
    
    // Reserved vpubchain
    // rTbU5TG6zXWWdTe2HQdHwEM7GVFR7xnN6f
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 1000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("ea4d7e3d7fd2ad3f569a21b62d19dbd4b2bb1c3d") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved vpubchain for primary round
    // rVSjQ6FntNMwidUoBcUsu9dB6QqQoDbmC8
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 1000000 * COIN;
    out->scriptPubKey = CScript() << 1564632000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("fe96ca68034a74d44bbc46cde9fa2036eb56d45b") << OP_EQUAL; // 2017-11-30
    txNew.vpout.push_back(out);


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VIRCLE_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "Chinese economy dismays naysayers amid trade consultation with US";

    CMutableTransaction txNew;
    txNew.nVersion = VIRCLE_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;
    txNew.vpout.resize(nGenesisOutputs);
    for (size_t k = 0; k < nGenesisOutputs; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    // Community Initative 1
    // RYVDqsLVzwrP4aC3dFAfEXAip2BDWznzDp
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 4500000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("fe915b900012f13de9a8ec582c3bab87e17142b6") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative 2 
    // RGbEf3UhnKFAZn16tbCrDT4eh1GsgPTLqa
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 4500000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("5032851531c49e3607991b5bf9753ac95254816c") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Vircle 
    // RBNytppxP49DX1zvDmUGsZFHitrE7owa59
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 5000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("1708938d91d09eacdc8cf11e9da069f94f7c051f") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Vircle for primary round
    // RAfggmhaVqFduaWfYkwda1qsKccaHAMuBt
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 108800 * COIN;
    out->scriptPubKey = CScript() << 1564763400 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("0f392856e13200efef5989d82271d2bc7825d550") << OP_EQUAL; // 2019-08-03
    txNew.vpout.push_back(out);

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VIRCLE_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}


/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        // consensus.nSubsidyHalvingInterval = 210000;
        consensus.nSubsidyHalvingInterval = 525600; //for benyuan blockchain
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 1510272000; // 2017-11-10 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x5C791EC0;       // 2019-03-01 12:00:00
        consensus.csp2shTime = 0x5C791EC0;          // 2019-03-01 12:00:00
        consensus.smsg_fee_time = 0xFFFFFFFF;       // 2106 TODO: lower
        consensus.bulletproof_time = 0xFFFFFFFF;    // 2106 TODO: lower
        consensus.rct_time = 0xFFFFFFFF;            // 2106 TODO: lower

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;

        consensus.powLimit = uint256S("000000000000bfffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000467b28adaecf2f81c8");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000ee0141b0e3537d376a09660ffde7548c11c188518ef4fbca889e90f4dc67"); // 0

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xa5;
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xd6;
        // nDefaultPort = 51758;
        nDefaultPort = 56258;   //for benyuan
        nBIP44ID = 0x8000002C;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 1 minutes
        nTargetSpacing = 60;           // 1 minutes for benyuan
        nTargetTimespan = 24 * 60;      // 24 mins

        AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlockMainNet(1564632000, 44396,  0x1f00ffff); // 2019-08-1 12:00:00
        consensus.hashGenesisBlock = genesis.GetHash();
        
        bool fNegative;
        bool fOverflow;
        arith_uint256 bnTarget;

        uint32_t i;
        uint256 hash;

        bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
                std::cout << "target:" << bnTarget.GetHex() << std::endl;

                for (i = 0; i < 4294967295; i++) {
                genesis.nNonce=i;
                hash = genesis.GetHash();
                //std::cout << "hash:" << hash.GetHex() << std::endl;
                if (UintToArith256(hash) <= bnTarget){
                        //std::cout << "nonce:" << i << std::endl;
                        break;
                }
        }
        hash = genesis.GetHash();
        if (UintToArith256(hash) <= bnTarget){
                std::cout << "nonce1:" << i << std::endl;
        }
        
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
	
        assert(consensus.hashGenesisBlock == uint256S("0x0000f758767f225ae01beb765fcaeb035473ece730e4fb47d63f48b993532552"));
        assert(genesis.hashMerkleRoot == uint256S("0x470979befd6ecedd177afbe1f006a1947942ecdd5de391cc6caaaeb37233f9af"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xc28e284ca568b6747a33043b2bd089275a71566d964433f356be0520907c39c7"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        //vSeeds.emplace_back("mainnet-seed.vircle.io");
        //vSeeds.emplace_back("dnsseed-mainnet.vircle.io");
        //vSeeds.emplace_back("mainnet.vircle.io");
        vSeeds.emplace_back("52.82.109.52");
        vSeeds.emplace_back("52.83.66.3");


        vDevFundSettings.emplace_back(0, DevFundSettings("RBNytppxP49DX1zvDmUGsZFHitrE7owa59", 5, 60));
        vDevFundSettings.emplace_back(consensus.OpIsCoinstakeTime, DevFundSettings("RBNytppxP49DX1zvDmUGsZFHitrE7owa59", 5, 60));


        base58Prefixes[PUBKEY_ADDRESS]     = {0x38}; // P
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3c};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[SECRET_KEY]         = {0x6c};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x69, 0x6e, 0x82, 0xd1}; // PPAR
        base58Prefixes[EXT_SECRET_KEY]     = {0x8f, 0x1d, 0xae, 0xb8}; // XPAR
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("ph","ph"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("pr","pr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("pl","pl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("pj","pj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("px","px"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("pep","pep"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("pex","pex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ps","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("pek","pek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("pea","pea"+3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("pcs","pcs"+3);

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0,       uint256S("0x0000f758767f225ae01beb765fcaeb035473ece730e4fb47d63f48b993532552")},
                // { 5000,    uint256S("0x48236bab754d77f1651fd94f8a75a66c3f4e994eed8774e7fa2c16ad4604c247")},
                // { 15000,   uint256S("0x81346b95c7b958c5e290c6f90f6ff901da2ebb501b615a80fb9efb6d439a7497")},
                // { 30000,   uint256S("0x9f3e8ab012e03da1cac2ed5d1672d7ad6c00db168aab34af6aab8e4279c01cb0")},
            }
        };

        chainTxData = ChainTxData {
            // Data from rpc: getchaintxstats 4096 ff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c
            /* nTime    */ 1564632000,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        // consensus.nSubsidyHalvingInterval = 210000;
        consensus.nSubsidyHalvingInterval = 525600; //for benyuan blockchain
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0x5C67FB40;          // 2019-02-16 12:00:00
        consensus.smsg_fee_time = 0x5C67FB40;       // 2019-02-16 12:00:00
        consensus.bulletproof_time = 0x5C67FB40;    // 2019-02-16 12:00:00
        consensus.rct_time = 0;

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
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
        consensus.nMinimumChainWork = uint256S("0xd7");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000523baa77736a9b7e6b8f7a363caa8b05c84a16624801a7f4cdfa72ee98d"); // 0

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x0a;
        pchMessageStart[1] = 0x1b;
        pchMessageStart[2] = 0x3c;
        pchMessageStart[3] = 0x4d;
        nDefaultPort = 57258;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 1 minutes
        nTargetSpacing = 60;           // 1 minutes
        nTargetTimespan = 24 * 60;      // 24 mins


        AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        //genesis = CreateGenesisBlockTestNet(1502309248, 5924, 0x1f00ffff);
        genesis = CreateGenesisBlockTestNet(1564632000, 96751, 0x1f00ffff); //2019-05-14
        consensus.hashGenesisBlock = genesis.GetHash();
	
        bool fNegative;
        bool fOverflow;
        arith_uint256 bnTarget;

        uint32_t i;
        uint256 hash;

        bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
        std::cout << "target:" << bnTarget.GetHex() << std::endl;

        for (i = 0; i < 4294967295; i++) {
            genesis.nNonce=i;
            hash = genesis.GetHash();
            //std::cout << "hash:" << hash.GetHex() << std::endl;
            if (UintToArith256(hash) <= bnTarget){
                //std::cout << "nonce:" << i << std::endl;
                break;
            }
        }
        hash = genesis.GetHash();
        if (UintToArith256(hash) <= bnTarget){
                std::cout << "nonce1:" << i << std::endl;
        }
	
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
 	    
        assert(consensus.hashGenesisBlock == uint256S("0x0000e97b8080f0ec138456b1d18d1d8637304615559e39b9ff33cd3eaf2edbdc"));
        assert(genesis.hashMerkleRoot == uint256S("0x049caf11f9585ca764abca3984f5b2ba3aabea9f9a38d426dd5c34acbc92c005"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xac3f50231de18ad3604a2bcd9eecf70bd7181f7b0ef0fddf083b59aa0964e2c7"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.vircle.io");
        //vSeeds.emplace_back("dnsseed-testnet.vircle.io");
        vSeeds.emplace_back("52.82.109.52");
        vSeeds.emplace_back("52.83.66.3");

        vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rVSjQ6FntNMwidUoBcUsu9dB6QqQoDbmC8", 10, 100)));

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
		        {0,     uint256S("0x0000e97b8080f0ec138456b1d18d1d8637304615559e39b9ff33cd3eaf2edbdc")},
                // {15000, uint256S("0x4d170758b0e382df416a2ccf7cb3be70b01ccda56c75e4d3408759693bb8b349")},
                // {30000, uint256S("0x8cfc31c0a75d55040eaba60a4069aa2515d22d0ab518bfe4a77c3f9550fa9827")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 eecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc
            /* nTime    */ 1564632000,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;

        consensus.smsg_fee_period = 50;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 4300;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 1;

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x0c;
        nDefaultPort = 11958;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        SetLastImportHeight();

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        //genesis = CreateGenesisBlockRegTest(1487714923, 0, 0x207fffff);
        genesis = CreateGenesisBlockRegTest(1555488002, 0, 0x207fffff);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
        */
        assert(consensus.hashGenesisBlock == uint256S("0xb18c0be1691609a6ff5fa2fe52140a5b4b3363443a910b178e742560ca91c265"));
        assert(genesis.hashMerkleRoot == uint256S("0x2af16a74a4cfa57ae22752b495aff4653a9b24be2a42e843d0ed2602a9224d16"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x16dc1d3c33b8405083e0292d408052a015806827d52585bc4b02b8feddba7ee6"));
        
        //assert(consensus.hashGenesisBlock == uint256S("0x6cd174536c0ada5bfa3b8fde16b98ae508fff6586f2ee24cf866867098f25907"));
        //assert(genesis.hashMerkleRoot == uint256S("0xf89653c7208af2c76a3070d436229fb782acbd065bd5810307995b9982423ce7"));
        //assert(genesis.hashWitnessMerkleRoot == uint256S("0x36b66a1aff91f34ab794da710d007777ef5e612a320e1979ac96e5f292399639"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "bcrt";

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
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

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
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


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN) {
        return ((CMainParams*)params.get())->SetOld();
    }
    if (params->NetworkID() == CBaseChainParams::REGTEST) {
        return ((CRegTestParams*)params.get())->SetOld();
    }
};

void ResetParams(std::string sNetworkId, bool fVircleModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fVircleModeIn) {
        SetOldParams(globalChainParams);
    }
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};
