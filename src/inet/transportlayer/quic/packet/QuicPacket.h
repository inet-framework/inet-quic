//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef INET_APPLICATIONS_QUIC_QUICPACKET_H_
#define INET_APPLICATIONS_QUIC_QUICPACKET_H_

#include <vector>

#include "PacketHeader_m.h"
#include "QuicFrame.h"
#include "inet/common/packet/Packet.h"

extern "C" {
#include "picotls.h"
#include "picotls/openssl_opp.h"
}

namespace inet {
namespace quic {

struct EncryptionKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> hpkey;

    static EncryptionKey newInitial(ptls_iovec_t initial_random, const char *hkdf_label) {
        ptls_hash_algorithm_t *hash = &ptls_openssl_opp_sha256;

        static const uint8_t quic_v1_salt[] = {
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a
        };

        uint8_t initial_secret[32];
        ptls_hkdf_extract(hash, initial_secret, ptls_iovec_init(quic_v1_salt, sizeof(quic_v1_salt)), initial_random);

        ptls_iovec_t null_iovec = ptls_iovec_init(NULL, 0);

        uint8_t secret[32]; // "client_secret"/"server_secret"
        ptls_hkdf_expand_label(hash, secret, 32, ptls_iovec_init(initial_secret, 32), hkdf_label, null_iovec, NULL);
        ptls_iovec_t secret_iovec = ptls_iovec_init(secret, 32);

        std::vector<uint8_t> key(16);
        ptls_hkdf_expand_label(hash, key.data(), key.size(), secret_iovec, "quic key", null_iovec, NULL);

        std::vector<uint8_t> iv(12);
        ptls_hkdf_expand_label(hash, iv.data(), iv.size(), secret_iovec, "quic iv", null_iovec, NULL);

        std::vector<uint8_t> hpkey(16);
        ptls_hkdf_expand_label(hash, hpkey.data(), hpkey.size(), secret_iovec, "quic hp", null_iovec, NULL);

        return {key, iv, hpkey};
    }
};

enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData
};

class QuicPacket {
public:
    QuicPacket(std::string name);
    virtual ~QuicPacket();

    uint64_t getPacketNumber();
    bool isCryptoPacket();

    void setHeader(Ptr<PacketHeader> header);
    void addFrame(QuicFrame *frame);
    Packet *createOmnetPacket(const char *secret);
    virtual void onPacketLost();
    virtual void onPacketAcked();

    virtual void setIBit(bool iBit);
    virtual bool isDplpmtudProbePacket();

    virtual bool containsFrame(QuicFrame *otherFrame);
    virtual int getMemorySize();

    bool countsAsInFlight() {
        return countsInFlight;
    }
    omnetpp::simtime_t getTimeSent() {
        return timeSent;
    }
    void setTimeSent(omnetpp::simtime_t time) {
        timeSent = time;
    }
    bool isAckEliciting() {
        return ackEliciting;
    }
    size_t getSize() {
        return size;
    }
    size_t getDataSize() {
        return dataSize;
    }
    std::vector<QuicFrame*> *getFrames() {
        return &frames;
    }
    std::string getName() {
        return name;
    }
    Ptr<PacketHeader> getHeader() {
        return header;
    }

private:
    bool ackEliciting;
    bool countsInFlight;
    omnetpp::simtime_t timeSent;
    Ptr<PacketHeader> header;
    std::vector<QuicFrame*> frames;
    size_t size;
    size_t dataSize;
    std::string name;

};

} /* namespace quic */
} /* namespace inet */

#endif /* INET_APPLICATIONS_QUIC_QUICPACKET_H_ */
