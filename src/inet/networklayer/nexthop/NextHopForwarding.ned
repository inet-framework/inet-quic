//
// Copyright (C) 2012 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.networklayer.nexthop;

import inet.common.SimpleModule;

//
// A simplified next hop forwarding that routes
// datagrams using different kinds of network addresses.
//
simple NextHopForwarding extends SimpleModule
{
    parameters:
        @class(NextHopForwarding);
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule;
        string arpModule;
        double procDelay @unit(s) = default(0s);
        int hopLimit = default(32);
        int headerLength @unit(B) = default(10B);
        @display("i=block/routing");
        @signal[packetDropped](type=inet::Packet);
        @signal[packetSentToUpper](type=inet::Packet);
    gates:
        input transportIn @labels(TcpHeader,UdpHeader);
        output transportOut @labels(TcpHeader,UdpHeader);
        input queueIn @labels(NextHopDatagram);
        output queueOut @labels(NextHopDatagram);
}

