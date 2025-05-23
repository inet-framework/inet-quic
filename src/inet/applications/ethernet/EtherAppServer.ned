//
// Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package inet.applications.ethernet;

import inet.common.SimpleModule;

//
// Server side of the ~EtherAppClient model -- generates packets containing
// ~EtherAppResp chunks with the number of bytes requested by the client in
// corresponding ~EtherAppReq. It should be connected directly to ~Ieee8022Llc
// module.
//
simple EtherAppServer extends SimpleModule
{
    parameters:
        @class(EtherAppServer);
        int localSAP = default(0xf1);
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // Extra time after lifecycle stop operation is finished
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

