//
// Copyright (C) 2004 OpenSim Ltd.
// Copyright (C) 2009-2011 Thomas Reschka
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.common.checksum.ChecksumMode;
import inet.transportlayer.contract.TransportHeaderBase;

namespace inet::tcp;

cplusplus {{
const B TCP_MIN_HEADER_LENGTH = B(20);  // default TCP header length: 20 bytes without options
const B TCP_MAX_HEADER_LENGTH = B(60);  // maximum TCP header length (base + options): 60 = 15 * 4 bytes

const B TCP_OPTIONS_MAX_SIZE     = B(40);  // 40 bytes, 15 * 4 bytes (15 is the largest number in 4 bits length data offset field), TCP_MAX_HEADER_OCTETS - TCP_HEADER_OCTETS = 40
const B TCP_OPTION_HEAD_SIZE = B(2);       // 2 bytes, type and length
const B TCP_OPTION_SACK_MIN_SIZE = B(10);  // 10 bytes, option length = 8 * n + 2 bytes (NOP)
const B TCP_OPTION_SACK_ENTRY_SIZE = B(8); // sack entry size
const B TCP_OPTION_TS_SIZE       = B(12);  // 12 bytes, option length = 10 bytes + 2 bytes (NOP)

}}

enum TcpConstants {
    // maximum allowed sack entry number, if no other options are used
    TCP_MAX_SACK_ENTRIES = 4;
}

//
// TCP Option Numbers
// Reference: http://www.iana.org/assignments/tcp-parameters/
// Date: 2011-07-02
//
// Note: Options not yet implemented should stay commented out
//
enum TcpOptionNumbers
{
    TCPOPTION_END_OF_OPTION_LIST = 0;                   // RFC 793, LENGTH: 1 Byte
    TCPOPTION_NO_OPERATION = 1;                         // RFC 793, LENGTH: 1 Byte
    TCPOPTION_MAXIMUM_SEGMENT_SIZE = 2;                 // RFC 793, LENGTH: 4 Bytes
    TCPOPTION_WINDOW_SCALE = 3;                         // RFC 1323, LENGTH: 3 Bytes
    TCPOPTION_SACK_PERMITTED = 4;                       // RFC 2018, LENGTH: 2 Bytes
    TCPOPTION_SACK = 5;                                 // RFC 2018, LENGTH: N (max. N = 4) 8 * n + 2 Bytes  => 32 + 2 + 2 * NOP = 36 Bytes; If TIMESTAMP option is used with SACK: max. n = 3 => 12 Bytes (for Timestamp) + 28 Bytes (for SACK) = 40 Bytes
//    TCPOPTION_ECHO = 6;                               // (obsoleted by option 8) RFC 1072 & RFC 6247, LENGTH: 6 Bytes
//    TCPOPTION_ECHO_REPLY = 7;                         // (obsoleted by option 8) RFC 1072 & RFC 6247, LENGTH: 6 Bytes
    TCPOPTION_TIMESTAMP = 8;                            // RFC 1323, LENGTH: 10 Bytes
//    TCPOPTION_PARTIAL_ORDER_CONNECTION_PERMITTED = 9; // (obsolete) RFC 1693 & RFC 6247, LENGTH: 2 Bytes
//    TCPOPTION_PARTIAL_ORDER_SERVICE_PROFILE = 10;     // (obsolete) RFC 1693 & RFC 6247, LENGTH: 3 Bytes
//    TCPOPTION_CC = 11;                                // (obsolete) RFC 1644 & RFC 6247, LENGTH: -
//    TCPOPTION_CC_NEW = 12;                            // (obsolete) RFC 1644 & RFC 6247, LENGTH: -
//    TCPOPTION_CC_ECHO = 13;                           // (obsolete) RFC 1644 & RFC 6247, LENGTH: -
//    TCPOPTION_TCP_ALTERNATE_CHECKSUM_REQUEST = 14;    // (obsolete) RFC 1146 & RFC 6247, LENGTH: 3 Bytes
//    TCPOPTION_TCP_ALTERNATE_CHECKSUM_DATA = 15;       // (obsolete) RFC 1146 & RFC 6247, LENGTH: N
//  TCPOPTION_SKEETER = 16;                             // [Knowles], LENGTH: -
//  TCPOPTION_BUBBA = 17;                               // [Knowles], LENGTH: -
//  TCPOPTION_TRAILER_CHECKSUM_OPTION = 18;             // [Subbu & Monroe], LENGTH: 3Bytes
//    TCPOPTION_MD5_SIGNATURE_OPTION = 19;              // (obsoleted by option 29) RFC 2385, LENGTH: 18 Bytes
//  TCPOPTION_SCPS_CAPABILITIES = 20;                   // [Scott], LENGTH: -
//  TCPOPTION_SELECTIVE_NEGATIVE_ACKNOWLEDGEMENTS = 21; // [Scott], LENGTH: -
//  TCPOPTION_RECORD_BOUNDARIES = 22;                   // [Scott], LENGTH: -
//  TCPOPTION_CORRUPTION_EXPERIENCED = 23;              // [Scott], LENGTH: -
//  TCPOPTION_SNAP = 24;                                // [Sukonnik], LENGTH: -
//  TCPOPTION_UNASSIGNED = 25;                          // released 2000-12-18 [-], LENGTH: -
//  TCPOPTION_TCP_COMPRESSION_FILTER = 26;              // [Bellovin], LENGTH: -
//  TCPOPTION_QUICK_START_RESPONSE = 27;                // RFC 4782, LENGTH: 8 Bytes
//  TCPOPTION_USER_TIMEOUT_OPTION = 28;                 // RFC 5482, LENGTH: 4 Bytes
//  TCPOPTION_AUTHENTICATION_OPTION = 29;               // RFC 5925, LENGTH: -
//    TCPOPTION kinds 30-252 Unassigned
//  TCPOPTION_RFC3692_STYLE_EXPERIMENT_1 = 253;         // RFC 4727, LENGTH: N
//  TCPOPTION_RFC3692_STYLE_EXPERIMENT_2 = 254;         // RFC 4727, LENGTH: N
};

//
// This structure represents a single SACK (selective acknowledgment):
//
class SackItem extends cObject
{
    @packetData;
    unsigned int start;     // start seq no. of sack block
    unsigned int end;       // end seq no. of sack block
}

class Sack extends SackItem
{
}

cplusplus(Sack) {{
  public:
    Sack(unsigned int start_par, unsigned int end_par) { setSegment(start_par, end_par); }
    virtual bool empty() const;
    virtual bool contains(const Sack& other) const;
    virtual void clear();
    virtual void setSegment(unsigned int start_par, unsigned int end_par);
    virtual std::string str() const override;
}}

// Header Options (optional):
class TcpOption extends cObject
{
    @packetData;
    TcpOptionNumbers kind;            // option kind
    unsigned short length = 1;                    // option length
}

class TcpOptionEnd extends TcpOption
{
    kind = TCPOPTION_END_OF_OPTION_LIST;
    length = 1;
}

class TcpOptionNop extends TcpOption
{
    kind = TCPOPTION_NO_OPERATION;
    length = 1;
}

class TcpOptionMaxSegmentSize extends TcpOption
{
    kind = TCPOPTION_MAXIMUM_SEGMENT_SIZE;
    length = 4;
    uint16_t maxSegmentSize;   // uint16_t
}

class TcpOptionWindowScale extends TcpOption
{
    kind = TCPOPTION_WINDOW_SCALE;
    length = 3;
    unsigned short windowScale;   // uint8_t
}

class TcpOptionSackPermitted extends TcpOption
{
    kind = TCPOPTION_SACK_PERMITTED;
    length = 2;
}

class TcpOptionSack extends TcpOption
{
    kind = TCPOPTION_SACK;
    length = 2;     // 2 + getSackArraySize() * 8
    SackItem sackItem[];
}

class TcpOptionTimestamp extends TcpOption
{
    kind = TCPOPTION_TIMESTAMP;
    length = 10;
    uint32_t   senderTimestamp;
    uint32_t   echoedTimestamp;
}

class TcpOptionUnknown extends TcpOption
{
    kind = static_cast<TcpOptionNumbers>(-1);
    uint8_t bytes[];
}

//
// Represents a TCP segment, to be used with the ~Tcp module.
//
// TCP header fields not explicitly modelled: work on going
// - Data Offset (number of 32 bit words in the header): represented
//   by cMessage::length().
// - Reserved (reserved for future use)
// - Checksum (header checksum): modelled by cMessage::hasBitError()
// - Header Options: Currently only EOL, NOP, MSS, WS, SACK_PERMITTED, SACK and TS are implemented
// - Padding
//
// cMessage::getKind() may be set to an arbitrary value: TCP entities will
// ignore it and use only the header fields (synBit, ackBit, rstBit).
//
class TcpHeader extends TransportHeaderBase
{
    chunkLength = TCP_MIN_HEADER_LENGTH;

    // Source Port
    uint16_t srcPort;

    // Destination Port
    uint16_t destPort;

    // Sequence Number: first sequence number of the first data octet
    // in the respective segment (except if SYN is set; then the the
    // seq. number is the initial seq. number (ISS) and the first data
    // octet is ISS + 1)
    uint32_t sequenceNo;

    // Acknowledgement Number: if ACK flag is set, this field contains
    // the next sequence number the sender of this segment is expecting
    // to receive
    uint32_t ackNo;

    // TCP Header Length including options
    B headerLength = TCP_MIN_HEADER_LENGTH;

    bool cwrBit; // CWR: congestion window reduced bit (RFC 3168)
    bool eceBit; // ECE: ECN-echo bit (RFC 3168)
    bool urgBit; // URG: urgent pointer field significant if set
    bool ackBit; // ACK: ackNo significant if set
    bool pshBit; // PSH: push function
    bool rstBit; // RST: reset the connection
    bool synBit; // SYN: synchronize seq. numbers
    bool finBit; // FIN: finish - no more data from sender

    // Window Size: the number of data octets beginning with the one indicated
    // in the acknowledgement field which the sender of this segment is
    // willing to accept
    uint16_t window;

    // Urgent Pointer: communicates the current value of the urgent pointer
    // as a positive offset from the sequence number in this segment. The
    // urgent pointer points to the sequence number of the octet following
    // the urgent data. This field is only be interpreted in segments with
    // the URG control bit set.
    uint16_t urgentPointer;

    uint16_t checksum = 0;
    ChecksumMode checksumMode = CHECKSUM_MODE_UNDEFINED;

    // Header options (optional)
    // Currently only EOL, NOP, MSS, WS, SACK_PERMITTED, SACK and TS are implemented
    TcpOption *headerOption[] @owned;
}

cplusplus(cc) {{
void doParsimPacking(omnetpp::cCommBuffer *b, TcpOption *t)
{
    b->packObject(t);
}

void doParsimUnpacking(omnetpp::cCommBuffer *b, TcpOption * &t)
{
    t = check_and_cast<TcpOption*>(b->unpackObject());
}

}}

cplusplus(TcpHeader) {{
  public:
    /**
     * Returns RFC 793 specified SEG.LEN:
     *     SEG.LEN = the number of octets occupied by the data in the segment
     *               (counting SYN and FIN)
     *
     */
    uint32_t getSynFinLen() const { return (finBit ? 1 : 0) + (synBit ? 1 : 0); }

    /** Calculate Length of TCP Options Array in bytes */
    virtual B getHeaderOptionArrayLength() const;

    /** Drops all TCP options of the TCP segment */
    virtual void dropHeaderOptions();

    // implements TransportHeaderBase functions:
    virtual unsigned int getSourcePort() const override { return getSrcPort(); }
    virtual void setSourcePort(unsigned int port) override { setSrcPort(port); }
    virtual unsigned int getDestinationPort() const override { return getDestPort(); }
    virtual void setDestinationPort(unsigned int port) override { setDestPort(port); }
    virtual std::string str() const override;
}}
