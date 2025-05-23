//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

// Cleanup and rewrite: Andras Varga, 2004

#include "inet/networklayer/ipv4/Icmp.h"

#include <string.h>

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolGroup.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/Checksum.h"
#include "inet/common/packet/dissector/ProtocolDissector.h"
#include "inet/common/packet/dissector/ProtocolDissectorRegistry.h"
#include "inet/common/stlutils.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"

namespace inet {

Define_Module(Icmp);

void Icmp::handleParameterChange(const char *name)
{
    if (!strcmp(name, "checksumMode"))
        checksumMode = parseChecksumMode(par("checksumMode"), false);
    else if (!strcmp(name, "quoteLength"))
        parseQuoteLengthParameter();
}

void Icmp::parseQuoteLengthParameter()
{
    quoteLength = B(par("quoteLength"));
    if (quoteLength < B(8))
        throw cRuntimeError("The quoteLength must be 8 bytes or larger");
}

void Icmp::initialize(int stage)
{
    SimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        ift.reference(this, "interfaceTableModule", true);
        rt.reference(this, "routingTableModule", true);
        checksumMode = parseChecksumMode(par("checksumMode"), false);
        parseQuoteLengthParameter();
    }
    if (stage == INITSTAGE_NETWORK_LAYER_PROTOCOLS) {
        registerService(Protocol::icmpv4, gate("transportIn"), gate("transportOut"));
        registerProtocol(Protocol::icmpv4, gate("ipOut"), gate("ipIn"));
    }
}

void Icmp::handleMessage(cMessage *msg)
{
    cGate *arrivalGate = msg->getArrivalGate();

    // process arriving ICMP message
    if (arrivalGate->isName("ipIn")) {
        EV_INFO << "Received " << msg << " from network protocol.\n";
        processIcmpMessage(check_and_cast<Packet *>(msg));
        return;
    }
    else
        throw cRuntimeError("Message %s(%s) arrived in unknown '%s' gate", msg->getName(), msg->getClassName(), msg->getArrivalGate()->getName());
}

bool Icmp::maySendErrorMessage(Packet *packet, int inputInterfaceId)
{
    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    Ipv4Address origSrcAddr = ipv4Header->getSrcAddress();
    Ipv4Address origDestAddr = ipv4Header->getDestAddress();

    // don't send ICMP error messages in response to broadcast or multicast messages
    if (origDestAddr.isMulticast() || origDestAddr.isLimitedBroadcastAddress() || possiblyLocalBroadcast(origDestAddr, inputInterfaceId)) {
        EV_DETAIL << "won't send ICMP error messages for broadcast/multicast message " << ipv4Header << endl;
        return false;
    }

    // don't send ICMP error messages response to unspecified, broadcast or multicast addresses
    if ((inputInterfaceId != -1 && origSrcAddr.isUnspecified())
            || origSrcAddr.isMulticast()
            || origSrcAddr.isLimitedBroadcastAddress()
            || possiblyLocalBroadcast(origSrcAddr, inputInterfaceId)) {
        EV_DETAIL << "won't send ICMP error messages to broadcast/multicast address, message " << ipv4Header << endl;
        return false;
    }

    // ICMP messages are only sent about errors in handling fragment zero of fragmented datagrams
    if (ipv4Header->getFragmentOffset() != 0) {
        EV_DETAIL << "won't send ICMP error messages about errors in non-first fragments" << endl;
        return false;
    }

    // do not reply with error message to error message
    if (ipv4Header->getProtocolId() == IP_PROT_ICMP) {
        const auto& recICMPMsg = packet->peekDataAt<IcmpHeader>(B(ipv4Header->getHeaderLength()));
        if (!isIcmpInfoType(recICMPMsg->getType())) {
            EV_DETAIL << "ICMP error received -- do not reply to it" << endl;
            return false;
        }
    }

    return true;
}

void Icmp::sendOrProcessIcmpPacket(Packet *packet, Ipv4Address origSrcAddr)
{
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::icmpv4);

    // if srcAddr is not filled in, we're still in the src node, so we just
    // process the ICMP message locally, right away
    if (origSrcAddr.isUnspecified()) {
        // pretend it came from the Ipv4 layer
        packet->addTag<L3AddressInd>()->setDestAddress(Ipv4Address::LOOPBACK_ADDRESS);    // FIXME maybe use configured loopback address

        // then process it locally
        processIcmpMessage(packet);
    }
    else {
        sendToIP(packet, origSrcAddr);
    }
}

void Icmp::sendPtbMessage(Packet *packet, int mtu)
{
    Enter_Method("sendPtbMessage(datagram, mtu=%d)", mtu);

    if (maySendErrorMessage(packet, -1)) {
        // assemble a message name
        char msgname[80];
        sprintf(msgname, "ICMP-PTB-#%" PRIu64 "-mtu%d", ++ctr, mtu);

        // debugging information
        EV_DETAIL << "sending ICMP PTB " << msgname << endl;

        // create and send ICMP packet
        Packet *errorPacket = new Packet(msgname);
        const auto& icmpPtb = makeShared<IcmpPtb>();
        icmpPtb->setMtu(mtu);
        // ICMP message length: the internet header plus the first quoteLength bytes of
        // the original datagram's data is returned to the sender.
        const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
        B curQuoteLength = std::min(B(packet->getDataLength()), ipv4Header->getHeaderLength() + quoteLength);
        errorPacket->insertAtBack(packet->peekDataAt(b(0), curQuoteLength));
        insertChecksum(icmpPtb, errorPacket);
        errorPacket->insertAtFront(icmpPtb);

        sendOrProcessIcmpPacket(errorPacket, ipv4Header->getSrcAddress());
    }
}

void Icmp::sendErrorMessage(Packet *packet, int inputInterfaceId, IcmpType type, IcmpCode code)
{
    Enter_Method("sendErrorMessage(datagram, type=%d, code=%d)", type, code);

    if (maySendErrorMessage(packet, inputInterfaceId)) {
        // assemble a message name
        char msgname[80];
        sprintf(msgname, "ICMP-error-#%" PRIu64 "-type%d-code%d", ++ctr, type, code);

        // debugging information
        EV_DETAIL << "sending ICMP error " << msgname << endl;

        // create and send ICMP packet
        Packet *errorPacket = new Packet(msgname);
        const auto& icmpHeader = makeShared<IcmpHeader>();
        icmpHeader->setType(type);
        icmpHeader->setCode(code);
        // ICMP message length: the internet header plus the first quoteLength bytes of
        // the original datagram's data is returned to the sender.
        const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
        B curQuoteLength = std::min(B(packet->getDataLength()), ipv4Header->getHeaderLength() + quoteLength);
        errorPacket->insertAtBack(packet->peekDataAt(B(0), curQuoteLength));
        insertChecksum(icmpHeader, errorPacket);
        errorPacket->insertAtFront(icmpHeader);

        sendOrProcessIcmpPacket(errorPacket, ipv4Header->getSrcAddress());
    }
}

bool Icmp::possiblyLocalBroadcast(const Ipv4Address& addr, int interfaceId)
{
    if ((addr.getInt() & 1) == 0)
        return false;

    if (rt->isLocalBroadcastAddress(addr))
        return true;

    // if the input interface is unconfigured, we won't recognize network-directed broadcasts because we don't what network we are on
    if (interfaceId != -1) {
        NetworkInterface *ie = ift->getInterfaceById(interfaceId);
        auto ipv4Data = ie->findProtocolData<Ipv4InterfaceData>();
        bool interfaceUnconfigured = (ipv4Data == nullptr) || ipv4Data->getIPAddress().isUnspecified();
        return interfaceUnconfigured;
    }
    else {
        // if all interfaces are configured, we are OK
        bool allInterfacesConfigured = true;
        for (int i = 0; i < ift->getNumInterfaces(); i++) {
            auto ipv4Data = ift->getInterface(i)->findProtocolData<Ipv4InterfaceData>();
            if ((ipv4Data == nullptr) || ipv4Data->getIPAddress().isUnspecified())
                allInterfacesConfigured = false;
        }

        return !allInterfacesConfigured;
    }
}

void Icmp::processIcmpMessage(Packet *packet)
{
    if (!verifyChecksum(packet)) {
        EV_WARN << "incoming ICMP packet has wrong checksum, dropped\n";
        // drop packet
        PacketDropDetails details;
        details.setReason(INCORRECTLY_RECEIVED);
        emit(packetDroppedSignal, packet, &details);
        delete packet;
        return;
    }

    const auto& icmpmsg = packet->peekAtFront<IcmpHeader>();
    switch (icmpmsg->getType()) {
        case ICMP_REDIRECT:
            // TODO implement redirect handling
            EV_ERROR << "ICMP_REDIRECT not implemented yet, packet " << EV_FORMAT_OBJECT(packet) << " dropped.\n";
            delete packet;
            break;

        case ICMP_DESTINATION_UNREACHABLE:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETER_PROBLEM: {
            // ICMP errors are delivered to the appropriate higher layer protocol
            const auto& bogusL3Packet = packet->peekDataAt<Ipv4Header>(icmpmsg->getChunkLength());
            int transportProtocol = bogusL3Packet->getProtocolId();
            if (transportProtocol == IP_PROT_ICMP) {
                // received ICMP error answer to an ICMP packet:
                // FIXME should send up dest unreachable answers to pingapps
                errorOut(packet);
            }
            else {
                if (!contains(transportProtocols, transportProtocol)) {
                    EV_ERROR << "Transport protocol " << transportProtocol << " not registered, packet dropped\n";
                    delete packet;
                }
                else {
                    auto dispatchProtocolReq = packet->addTagIfAbsent<DispatchProtocolReq>();
                    dispatchProtocolReq->setServicePrimitive(SP_INDICATION);
                    dispatchProtocolReq->setProtocol(ProtocolGroup::getIpProtocolGroup()->getProtocol(transportProtocol));
                    packet->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::icmpv4);
                    send(packet, "transportOut");
                }
            }
            break;
        }

        case ICMP_ECHO_REQUEST:
            processEchoRequest(packet);
            break;

        case ICMP_ECHO_REPLY:
            delete packet;
            break;

        case ICMP_TIMESTAMP_REQUEST:
            processEchoRequest(packet);
            break;

        case ICMP_TIMESTAMP_REPLY:
            delete packet;
            break;

        default:
            throw cRuntimeError("Unknown ICMP type %d", icmpmsg->getType());
    }
}

void Icmp::errorOut(Packet *packet)
{
    delete packet;
}

void Icmp::processEchoRequest(Packet *request)
{
    // turn request into a reply
    const auto& icmpReq = request->popAtFront<IcmpEchoRequest>();
    Packet *reply = new Packet((std::string(request->getName()) + "-reply").c_str());
    const auto& icmpReply = makeShared<IcmpEchoReply>();
    icmpReply->setIdentifier(icmpReq->getIdentifier());
    icmpReply->setSeqNumber(icmpReq->getSeqNumber());
    auto addressInd = request->getTag<L3AddressInd>();
    Ipv4Address src = addressInd->getSrcAddress().toIpv4();
    Ipv4Address dest = addressInd->getDestAddress().toIpv4();
    reply->insertAtBack(request->peekData());
    insertChecksum(icmpReply, reply);
    reply->insertAtFront(icmpReply);

    // swap src and dest
    // TODO check what to do if dest was multicast etc?
    // A. Ariza Modification 5/1/2011 clean the interface id, this forces the use of routing table in the Ipv4 layer
    auto addressReq = reply->addTag<L3AddressReq>();
    addressReq->setSrcAddress(addressInd->getDestAddress().toIpv4());
    addressReq->setDestAddress(addressInd->getSrcAddress().toIpv4());

    sendToIP(reply);
    delete request;
}

void Icmp::sendToIP(Packet *msg, const Ipv4Address& dest)
{
    msg->addTagIfAbsent<L3AddressReq>()->setDestAddress(dest);
    sendToIP(msg);
}

void Icmp::sendToIP(Packet *msg)
{
    EV_INFO << "Sending " << msg << " to lower layer.\n";
    msg->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
    msg->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::icmpv4);
    send(msg, "ipOut");
}

void Icmp::handleRegisterService(const Protocol& protocol, cGate *gate, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterService");
}

void Icmp::handleRegisterProtocol(const Protocol& protocol, cGate *gate, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterProtocol");
    if (!strcmp("transportOut", gate->getBaseName())) {
        int protocolNumber = ProtocolGroup::getIpProtocolGroup()->findProtocolNumber(&protocol);
        if (protocolNumber != -1)
            transportProtocols.insert(protocolNumber);
    }
}

void Icmp::insertChecksum(ChecksumMode checksumMode, const Ptr<IcmpHeader>& icmpHeader, Packet *packet)
{
    icmpHeader->setChecksumMode(checksumMode);
    switch (checksumMode) {
        case CHECKSUM_DECLARED_CORRECT:
            // if the checksum mode is declared to be correct, then set the checksum to an easily recognizable value
            icmpHeader->setChksum(0xC00D);
            break;
        case CHECKSUM_DECLARED_INCORRECT:
            // if the checksum mode is declared to be incorrect, then set the checksum to an easily recognizable value
            icmpHeader->setChksum(0xBAAD);
            break;
        case CHECKSUM_COMPUTED: {
            // if the checksum mode is computed, then compute the checksum and set it
            icmpHeader->setChksum(0x0000); // make sure that the checksum is 0 in the header before computing the checksum
            MemoryOutputStream icmpStream;
            Chunk::serialize(icmpStream, icmpHeader);
            if (packet->getByteLength() > 0)
                Chunk::serialize(icmpStream, packet->peekDataAsBytes());
            uint16_t checksum = internetChecksum(icmpStream.getData());
            icmpHeader->setChksum(checksum);
            break;
        }
        default:
            throw cRuntimeError("Unknown checksum mode");
    }
}

bool Icmp::verifyChecksum(const Packet *packet)
{
    const auto& icmpHeader = packet->peekAtFront<IcmpHeader>(b(-1), Chunk::PF_ALLOW_INCORRECT);
    switch (icmpHeader->getChecksumMode()) {
        case CHECKSUM_DECLARED_CORRECT:
            // if the checksum mode is declared to be correct, then the check passes if and only if the chunks are correct
            return icmpHeader->isCorrect();
        case CHECKSUM_DECLARED_INCORRECT:
            // if the checksum mode is declared to be incorrect, then the check fails
            return false;
        case CHECKSUM_COMPUTED: {
            // otherwise compute the checksum, the check passes if the result is 0xFFFF (includes the received checksum)
            auto dataBytes = packet->peekDataAsBytes(Chunk::PF_ALLOW_INCORRECT);
            uint16_t checksum = internetChecksum(dataBytes->getBytes());
            // TODO delete these isCorrect calls, rely on checksum only
            return checksum == 0 && icmpHeader->isCorrect();
        }
        default:
            throw cRuntimeError("Unknown checksum mode");
    }
}

} // namespace inet

