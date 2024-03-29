# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_INCLUDES=-I$(builddir) $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBVIRCLE_SERVER=libvircle_server.a
LIBVIRCLE_COMMON=libvircle_common.a
LIBVIRCLE_CONSENSUS=libvircle_consensus.a
LIBVIRCLE_CLI=libvircle_cli.a
LIBVIRCLE_UTIL=libvircle_util.a
LIBVIRCLE_CRYPTO_BASE=crypto/libvircle_crypto_base.a
LIBVIRCLEQT=qt/libvircleqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBVIRCLE_SMSG=libvircle_smsg.a

if ENABLE_ZMQ
LIBVIRCLE_ZMQ=libvircle_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBVIRCLECONSENSUS=libvircleconsensus.la
endif
if ENABLE_WALLET
LIBVIRCLE_WALLET=libvircle_wallet.a
LIBVIRCLE_WALLET_TOOL=libvircle_wallet_tool.a
endif
if ENABLE_USBDEVICE
LIBVIRCLE_USBDEVICE=libvircle_usbdevice.a
endif

LIBVIRCLE_CRYPTO= $(LIBVIRCLE_CRYPTO_BASE)
if ENABLE_SSE41
LIBVIRCLE_CRYPTO_SSE41 = crypto/libvircle_crypto_sse41.a
LIBVIRCLE_CRYPTO += $(LIBVIRCLE_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBVIRCLE_CRYPTO_AVX2 = crypto/libvircle_crypto_avx2.a
LIBVIRCLE_CRYPTO += $(LIBVIRCLE_CRYPTO_AVX2)
endif
if ENABLE_SHANI
LIBVIRCLE_CRYPTO_SHANI = crypto/libvircle_crypto_shani.a
LIBVIRCLE_CRYPTO += $(LIBVIRCLE_CRYPTO_SHANI)
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBVIRCLE_CRYPTO) \
  $(LIBVIRCLE_UTIL) \
  $(LIBVIRCLE_COMMON) \
  $(LIBVIRCLE_CONSENSUS) \
  $(LIBVIRCLE_SERVER) \
  $(LIBVIRCLE_CLI) \
  $(LIBVIRCLE_WALLET) \
  $(LIBVIRCLE_WALLET_TOOL) \
  $(LIBVIRCLE_USBDEVICE) \
  $(LIBVIRCLE_SMSG) \
  $(LIBVIRCLE_ZMQ)

lib_LTLIBRARIES = $(LIBVIRCLECONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += vircled
endif

if BUILD_BITCOIN_CLI
  bin_PROGRAMS += vircle-cli
endif
if BUILD_BITCOIN_TX
  bin_PROGRAMS += vircle-tx
endif
if ENABLE_WALLET
if BUILD_BITCOIN_WALLET
  bin_PROGRAMS += vircle-wallet
endif
endif

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  addrdb.h \
  rctindex.h \
  addrman.h \
  attributes.h \
  banman.h \
  base58.h \
  bech32.h \
  bloom.h \
  blockencodings.h \
  blockfilter.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  chainparamsimport.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  index/base.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  anon.h \
  blind.h \
  interfaces/chain.h \
  interfaces/handler.h \
  interfaces/node.h \
  interfaces/wallet.h \
  key.h \
  key/stealth.h \
  key/extkey.h \
  key/mnemonic.h \
  unilib/uninorms.h \
  unilib/utf8.h \
  key/types.h \
  key/keyutil.h \
  key/wordlists/chinese_simplified.h \
  key/wordlists/chinese_traditional.h \
  key/wordlists/english.h \
  key/wordlists/french.h \
  key/wordlists/japanese.h \
  key/wordlists/spanish.h \
  key/wordlists/italian.h \
  key/wordlists/korean.h \
  key_io.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  logging.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  node/transaction.h \
  noui.h \
  optional.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  pos/kernel.h \
  pos/miner.h \
  protocol.h \
  psbt.h \
  random.h \
  reverse_iterator.h \
  reverselock.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/rpcutil.h \
  rpc/rawtransaction.h \
  rpc/register.h \
  rpc/util.h \
  scheduler.h \
  script/descriptor.h \
  script/ismine.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  shutdown.h \
  streams.h \
  smsg/db.h \
  smsg/crypter.h \
  smsg/net.h \
  smsg/smessage.h \
  smsg/rpcsmessage.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util/bip32.h \
  util/bytevectorhash.h \
  util/system.h \
  util/memory.h \
  util/moneystr.h \
  util/time.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  versionbitsinfo.h \
  walletinitinterface.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/psbtwallet.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  wallet/coinselection.h \
  wallet/rpchdwallet.h \
  wallet/hdwalletdb.h \
  wallet/hdwallet.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  usbdevice/usbdevice.h \
  usbdevice/rpcusbdevice.h \
  insight/addressindex.h \
  insight/spentindex.h \
  insight/timestampindex.h \
  insight/csindex.h \
  insight/insight.h \
  insight/rpc.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libvircle_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between bitcoind and bitcoin-qt
libvircle_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libvircle_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  bloom.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  checkpoints.cpp \
  consensus/tx_verify.cpp \
  httprpc.cpp \
  httpserver.cpp \
  index/base.cpp \
  index/txindex.cpp \
  interfaces/chain.cpp \
  interfaces/handler.cpp \
  interfaces/node.cpp \
  init.cpp \
  dbwrapper.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  node/transaction.cpp \
  noui.cpp \
  outputtype.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  policy/rbf.cpp \
  pow.cpp \
  pos/kernel.cpp \
  rest.cpp \
  rpc/anon.cpp \
  rpc/mnemonic.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/client.cpp \
  rpc/rpcutil.cpp \
  rpc/util.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  insight/insight.cpp \
  insight/rpc.cpp \
  $(BITCOIN_CORE_H)

if !ENABLE_WALLET
libvircle_server_a_SOURCES += dummywallet.cpp
endif

if ENABLE_ZMQ
libvircle_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libvircle_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp
endif

if ENABLE_USBDEVICE
libvircle_usbdevice_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(AM_CPPFLAGS) $(PROTOBUF_CFLAGS)
libvircle_usbdevice_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_usbdevice_a_CFLAGS = -DHAVE_HIDAPI $(AM_CFLAGS)
libvircle_usbdevice_a_SOURCES = \
  usbdevice/usbwrapper.cpp \
  usbdevice/usbwrapper.h \
  usbdevice/ledger/btchipApdu.h \
  usbdevice/ledger/ledgerLayer.h \
  usbdevice/ledger/ledgerLayer.c \
  usbdevice/ledger/dongleCommHidHidapi.h \
  usbdevice/ledger/dongleCommHidHidapi.c \
  usbdevice/usbdevice.cpp \
  usbdevice/debugdevice.h \
  usbdevice/debugdevice.cpp \
  usbdevice/ledgerdevice.h \
  usbdevice/ledgerdevice.cpp \
  usbdevice/trezor/messages.proto \
  usbdevice/trezor/messages-common.proto \
  usbdevice/trezor/messages-management.proto \
  usbdevice/trezor/messages-bitcoin.proto \
  usbdevice/trezordevice.h \
  usbdevice/trezordevice.cpp \
  usbdevice/rpcusbdevice.cpp
nodist_libvircle_usbdevice_a_SOURCES = \
  usbdevice/trezor/messages.pb.h \
  usbdevice/trezor/messages.pb.cc \
  usbdevice/trezor/messages-common.pb.h \
  usbdevice/trezor/messages-common.pb.cc \
  usbdevice/trezor/messages-management.pb.h \
  usbdevice/trezor/messages-management.pb.cc \
  usbdevice/trezor/messages-bitcoin.pb.h \
  usbdevice/trezor/messages-bitcoin.pb.cc
BUILT_SOURCES = $(nodist_libvircle_usbdevice_a_SOURCES)
endif

# wallet: shared between bitcoind and bitcoin-qt, but only linked
# when wallet enabled
libvircle_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_wallet_a_SOURCES = \
  interfaces/wallet.cpp \
  wallet/coincontrol.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/init.cpp \
  wallet/psbtwallet.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/hdwallet.cpp \
  wallet/hdwalletdb.cpp \
  wallet/rpchdwallet.cpp \
  blind.cpp \
  key/stealth.cpp \
  pos/miner.cpp \
  policy/rbf.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(BITCOIN_CORE_H)

libvircle_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libvircle_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libvircle_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libvircle_crypto_base_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

if USE_ASM
crypto_libvircle_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libvircle_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libvircle_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libvircle_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libvircle_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libvircle_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libvircle_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libvircle_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libvircle_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libvircle_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libvircle_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

crypto_libvircle_crypto_shani_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libvircle_crypto_shani_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libvircle_crypto_shani_a_CXXFLAGS += $(SHANI_CXXFLAGS)
crypto_libvircle_crypto_shani_a_CPPFLAGS += -DENABLE_SHANI
crypto_libvircle_crypto_shani_a_SOURCES = crypto/sha256_shani.cpp

# consensus: shared between all executables that validate any consensus rules.
libvircle_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h

# common: shared between bitcoind, and bitcoin-qt and non-server tools
libvircle_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_common_a_SOURCES = \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  anon.cpp \
  blind.cpp \
  key.cpp \
  key/keyutil.cpp \
  key/extkey.cpp \
  key/stealth.cpp \
  smsg/crypter.cpp \
  key/mnemonic.cpp \
  unilib/uninorms.cpp \
  unilib/utf8.cpp \
  key_io.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  policy/feerate.cpp \
  psbt.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/ismine.cpp \
  script/sign.cpp \
  script/standard.cpp \
  versionbitsinfo.cpp \
  warnings.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libvircle_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  logging.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/system.cpp \
  util/moneystr.cpp \
  util/strencodings.cpp \
  util/time.cpp \
  $(BITCOIN_CORE_H)


libvircle_smsg_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_smsg_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_smsg_a_SOURCES = \
  lz4/lz4.h \
  lz4/lz4.c \
  xxhash/xxhash.h \
  xxhash/xxhash.c \
  interfaces/handler.cpp \
  smsg/crypter.cpp \
  smsg/keystore.h \
  smsg/keystore.cpp \
  smsg/db.cpp \
  smsg/smessage.cpp \
  smsg/rpcsmessage.cpp


if GLIBC_BACK_COMPAT
libvircle_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: shared between bitcoin-cli and bitcoin-qt
libvircle_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libvircle_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libvircle_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)


nodist_libvircle_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
vircled_SOURCES = bitcoind.cpp
vircled_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
vircled_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
vircled_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vircled_SOURCES += bitcoind-res.rc
endif

vircled_LDADD = \
  $(LIBVIRCLE_SERVER) \
  $(LIBVIRCLE_WALLET) \
  $(LIBVIRCLE_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBVIRCLE_UTIL) \
  $(LIBVIRCLE_ZMQ) \
  $(LIBVIRCLE_CONSENSUS) \
  $(LIBVIRCLE_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBVIRCLE_SMSG) \
  $(LIBVIRCLE_USBDEVICE)

vircled_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)
if ENABLE_USBDEVICE
vircled_LDADD += $(USB_LIBS) $(HIDAPI_LIBS) $(PROTOBUF_LIBS)
endif

# bitcoin-cli binary #
#$(BITCOIN_CLI_NAME)_SOURCES = bitcoin-cli.cpp
vircle_cli_SOURCES = bitcoin-cli.cpp
vircle_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
vircle_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
vircle_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vircle_cli_SOURCES += bitcoin-cli-res.rc
endif

vircle_cli_LDADD = \
  $(LIBVIRCLE_CLI) \
  $(LIBUNIVALUE) \
  $(LIBVIRCLE_UTIL) \
  $(LIBVIRCLE_CRYPTO)

vircle_cli_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# bitcoin-tx binary #
vircle_tx_SOURCES = bitcoin-tx.cpp
vircle_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
vircle_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
vircle_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vircle_tx_SOURCES += bitcoin-tx-res.rc
endif

vircle_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBVIRCLE_COMMON) \
  $(LIBVIRCLE_UTIL) \
  $(LIBVIRCLE_CONSENSUS) \
  $(LIBVIRCLE_CRYPTO) \
  $(LIBSECP256K1)

vircle_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# bitcoin-wallet binary #
vircle_wallet_SOURCES = bitcoin-wallet.cpp
vircle_wallet_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
vircle_wallet_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
vircle_wallet_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
vircle_wallet_SOURCES += bitcoin-wallet-res.rc
endif

vircle_wallet_LDADD = \
  $(LIBVIRCLE_WALLET_TOOL) \
  $(LIBVIRCLE_SERVER) \
  $(LIBVIRCLE_WALLET) \
  $(LIBVIRCLE_COMMON) \
  $(LIBVIRCLE_CONSENSUS) \
  $(LIBVIRCLE_UTIL) \
  $(LIBVIRCLE_CRYPTO) \
  $(LIBVIRCLE_SMSG) \
  $(LIBVIRCLE_USBDEVICE) \
  $(LIBVIRCLE_ZMQ) \
  $(LIBUNIVALUE) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

vircle_wallet_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)
if ENABLE_USBDEVICE
vircle_wallet_LDADD += $(USB_LIBS) $(HIDAPI_LIBS) $(PROTOBUF_LIBS)
endif
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/vircleconsensus.h
libvircleconsensus_la_SOURCES = $(crypto_libvircle_crypto_base_a_SOURCES) $(libvircle_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libvircleconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libvircleconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libvircleconsensus_la_LIBADD = $(LIBSECP256K1) $(BOOST_LIBS)
libvircleconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libvircleconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/bitcoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bitcoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bitcoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bitcoin-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

if ENABLE_BIP70
%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<
endif

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
