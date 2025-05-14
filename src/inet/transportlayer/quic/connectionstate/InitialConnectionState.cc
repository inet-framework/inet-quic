/*
 * InitialConnectionState.cc
 *
 *  Created on: 7 Feb 2025
 *      Author: msvoelker
 */


#include "InitialConnectionState.h"
#include "InitialSentConnectionState.h"
#include "EstablishedConnectionState.h"
#include "../packet/ConnectionId.h"

extern "C" {
#include "picotls.h"
#include "picotls/openssl_opp.h"
}

namespace inet {
namespace quic {


ConnectionState *InitialConnectionState::processConnectAppCommand(cMessage *msg)
{
    // send client hello
    context->sendClientInitialPacket();

    return new InitialSentConnectionState(context);
}

void InitialConnectionState::processCryptoFrame(const Ptr<const CryptoFrameHeader>& frameHeader, Packet *pkt)
{
    if (frameHeader->getContainsTransportParameters()) {
        Ptr<const Chunk> payload = pkt->popAtFront();
        if (auto transportParametersExt = dynamicPtrCast<const TransportParametersExtension>(payload)) {
            EV_DEBUG << "got transport parameters: " << transportParametersExt << endl;
            context->getRemoteTransportParameters()->readExtension(transportParametersExt);
        }
        if (auto tlsPayload = dynamicPtrCast<const BytesChunk>(payload)) {
            EV_DEBUG << "got transport parameter bytes" << endl;
            ptls_buffer_t buffer;
            ptls_buffer_init(&buffer, (void*)"", 0);
            size_t epoch_offsets[5] = {0};
            std::vector<uint8_t> tlsBytes = tlsPayload->getBytes();
            ptls_handle_message(context->tls, &buffer, epoch_offsets, 0,
                tlsBytes.data(), tlsBytes.size(), nullptr);
            for (int i = 0; i < 5; i++) {
                if (epoch_offsets[i] > 0) {
                    std::cout << "epoch " << i << " offset: " << epoch_offsets[i] << endl;
                }
            }
        }
    }
}

ConnectionState *InitialConnectionState::processInitialPacket(const Ptr<const InitialPacketHeader>& packetHeader, Packet *pkt) {
    EV_DEBUG << "processInitialPacket in " << name << endl;

    ackElicitingPacket = false;
    processFrames(pkt, PacketNumberSpace::Initial);

    context->addDstConnectionId(packetHeader->getSrcConnectionId(), packetHeader->getSrcConnectionIdLength());
    context->accountReceivedPacket(packetHeader->getPacketNumber(), ackElicitingPacket, PacketNumberSpace::Initial, false);

    // send server hello
    context->sendServerInitialPacket();

    // send Encrypted Extensions, Certificate, Certificate Verify, and Finished
    context->sendHandshakePacket(true);

    return new EstablishedConnectionState(context);
}

} /* namespace quic */
} /* namespace inet */
