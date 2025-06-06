//
// Copyright (C) 2011 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.applications.ethernet;

import inet.common.SimpleModule;

//
// A simple traffic generator for the Ethernet model and the 802.11 model, and
// generally for any L2 model that accepts ~Ieee802SapReq tag on packets. It
// should be connected directly to ~Ieee8022Llc module.
//
simple EtherTrafGen extends SimpleModule
{
    parameters:
        @class(EtherTrafGen);
        string destAddress = default("");  // Destination MAC address, or module path name of destination station; empty means off
        string interface;   // Outgoing interface
        string interfaceTableModule;
        int ssap = default(-1);  // Llc ssap to set on outgoing packets
        int dsap = default(-1);  // Llc dsap to set on outgoing packets
        double startTime @unit(s) = default(this.sendInterval);  // Time of sending the first packet
        double stopTime @unit(s) = default(-1s);  // Time of finishing sending, negative values mean forever
        volatile double sendInterval @unit(s);  // Interval between sending bursts
        volatile int numPacketsPerBurst = default(1);  // Number of packets to send per burst (packets within a burst are sent at the same simulation time)
        volatile int packetLength @unit(B);  // Length of packets to send
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // Extra time after lifecycle stop operation finished
        double stopOperationTimeout @unit(s) = default(2s);    // Timeout value for lifecycle stop operation
        @display("i=block/app");
        @signal[packetSent](type=inet::Packet);
        @signal[packetReceived](type=inet::Packet);
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[endToEndDelay](title="end-to-end delay"; source="dataAge(packetReceived)"; unit=s; record=histogram,vector; interpolationmode=none);
    gates:
        input in @labels(Ieee802Ctrl/up) @messageKinds(inet::SocketStatusInd);
        output out @labels(Ieee802Ctrl/down) @messageKinds(inet::SocketCommandCode);
}

