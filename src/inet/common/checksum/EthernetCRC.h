//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#ifndef __INET_ETHERNETCRC_H
#define __INET_ETHERNETCRC_H

#include "inet/common/INETDefs.h"

namespace inet {

extern const uint32_t crc32_tab[];

uint32_t ethernetCRC(const unsigned char *buf, unsigned int bufsize, uint32_t crc = 0);

inline uint32_t ethernetCRC(const std::vector<uint8_t>& vec, uint32_t crc = 0) {
    return ethernetCRC(vec.data(), vec.size(), crc);
}

} // namespace inet

/*
 * Ethernet CRC32 polynomials (big- and little-endian versions).
 */
#define ETHER_CRC_POLY_LE    0xedb88320
#define ETHER_CRC_POLY_BE    0x04c11db6

#endif

