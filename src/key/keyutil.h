// Copyright (c) 2017 The Vircle Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef VIRCLE_KEY_KEYUTIL_H
#define VIRCLE_KEY_KEYUTIL_H

#include <vector>
#include <inttypes.h>

uint32_t BitcoinChecksum(uint8_t *p, uint32_t nBytes);
void AppendChecksum(std::vector<uint8_t> &data);
bool VerifyChecksum(const std::vector<uint8_t> &data);


#endif  // VIRCLE_KEY_KEYUTIL_H
