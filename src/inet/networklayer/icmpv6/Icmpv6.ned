//
// Copyright (C) 2005 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.networklayer.icmpv6;

import inet.common.SimpleModule;

//
// ICMPv6 implementation.
//
// @see ~Ipv6, ~Ipv6RoutingTable, ~Ipv6NeighbourDiscovery
//#FIXME gate descriptions needed...
//
simple Icmpv6 extends SimpleModule
{
    parameters:
        @class(Icmpv6);
        string interfaceTableModule;   // The path to the InterfaceTable module
        string checksumMode @enum("declared", "computed") = default("declared");
        @display("i=block/control");
    gates:
        input transportIn;
        output transportOut;
        input ipv6In;
        output ipv6Out;
}

