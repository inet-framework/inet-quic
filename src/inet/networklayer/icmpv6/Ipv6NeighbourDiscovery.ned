//
// Copyright (C) 2005 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.networklayer.icmpv6;

import inet.common.SimpleModule;

//
// Implements IPv6 Neighbor Discovery.
//
// An overview of the IPv6 implementation in the INET Framework is
// provided <a href="ipv6overview.html">here</a>.
//
// @see ~Ipv6, ~Ipv6RoutingTable, ~Icmpv6
//
simple Ipv6NeighbourDiscovery extends SimpleModule
{
    parameters:
        @class(Ipv6NeighbourDiscovery);
        string interfaceTableModule;   // The path to the InterfaceTable module
        string checksumMode @enum("declared", "computed") = default("declared");
        string icmpv6Module;
        string xmipv6Module;
        string routingTableModule;
        double minIntervalBetweenRAs @unit(s) = default(30ms); // MinRtrAdvInterval:  0.03 sec for MIPv6
        double maxIntervalBetweenRAs @unit(s) = default(70ms);  // MaxrtrAdvInterval: 0.07 sec for MIPv6
        @display("i=block/network");
        @signal[startDad](type=long); // Emits value=1
        @statistic[startDad](title="DAD started";record=count,vector);
    gates:
        input ipv6In;
        output ipv6Out;
}

