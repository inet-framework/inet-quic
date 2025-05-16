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

namespace inet {
namespace quic {


ConnectionState *InitialConnectionState::processConnectAppCommand(cMessage *msg)
{
    // send client hello
    context->sendClientInitialPacket();

    return new InitialSentConnectionState(context);
}

ConnectionState *InitialConnectionState::processConnectAndSendAppCommand(cMessage *msg)
{
    Packet *pkt = check_and_cast<Packet *>(msg);
    const char *clientToken = pkt->getTag<QuicNewToken>()->getToken();
    uint32_t token = context->processClientTokenExtractToken(clientToken);

    // send client hello
    context->sendClientInitialPacket(token);

    auto streamId = pkt->getTag<QuicStreamReq>()->getStreamID();
    context->newStreamData(streamId, pkt->peekData());

    return new InitialSentConnectionState(context);
}

void InitialConnectionState::processCryptoFrame(const Ptr<const CryptoFrameHeader>& frameHeader, Packet *pkt)
{
    if (frameHeader->getContainsTransportParameters()) {
        auto transportParametersExt = staticPtrCast<const TransportParametersExtension>(pkt->popAtFront());
        EV_DEBUG << "got transport parameters: " << transportParametersExt << endl;
        context->getRemoteTransportParameters()->readExtension(transportParametersExt);
    }
}

ConnectionState *InitialConnectionState::processInitialPacket(const Ptr<const InitialPacketHeader>& packetHeader, Packet *pkt) {
    EV_DEBUG << "processInitialPacket in " << name << endl;

    ackElicitingPacket = false;
    processFrames(pkt, PacketNumberSpace::Initial);

    context->addDstConnectionId(packetHeader->getSrcConnectionId(), packetHeader->getSrcConnectionIdLength());
    context->accountReceivedPacket(packetHeader->getPacketNumber(), ackElicitingPacket, PacketNumberSpace::Initial, false);

    if (packetHeader->getTokenLength() > 0) {
        uint32_t token = packetHeader->getToken();
        if (context->getUdpSocket()->doesTokenExist(token, context->getPath()->getRemoteAddr())) {
            EV_DEBUG << "InitialConnectionState::processInitialPacket: Found contained token, address validated" << endl;
            context->addConnectionForInitialConnectionId(packetHeader->getDstConnectionId());
        }
    }
    // send server hello
    context->sendServerInitialPacket();

    // send Encrypted Extensions, Certificate, Certificate Verify, and Finished
    context->sendHandshakePacket(true);

    return new EstablishedConnectionState(context);
}

} /* namespace quic */
} /* namespace inet */
