//
// Copyright (C) 2008 Juan-Carlos Maureira
// Copyright (C) INRIA
// Copyright (C) 2013 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package inet.applications.dhcp;

import inet.common.SimpleModule;
import inet.applications.contract.IApp;

//
// Implements the DHCP client protocol. DHCP (Dynamic Host Configuration Protocol),
// described in RFC 2131, provides configuration parameters to Internet hosts.
// Requires UDP.
//
// @see ~DhcpServer, ~DhcpMessage
//
simple DhcpClient extends SimpleModule like IApp
{
    parameters:
        @class(DhcpClient);
        string interfaceTableModule; // Path to the InterfaceTable module
        string routingTableModule; // Path to the Ipv4RoutingTable module
        string interface = default(""); // Which NIC should be configured (i.e. wlan0, eth1 etc.)
        double startTime @unit(s) = default(0s); // Starting time of DHCP initialization
        @display("i=block/app2");
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // Extra time after lifecycle stop operation finished
        double stopOperationTimeout @unit(s) = default(2s);    // Timeout value for lifecycle stop operation
        @selfMessageKinds(inet::DhcpTimerType);
    gates:
        input socketIn @labels(UdpCommand/up);
        output socketOut @labels(UdpCommand/down);
}

