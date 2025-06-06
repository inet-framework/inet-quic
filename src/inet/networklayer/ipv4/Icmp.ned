//
// Copyright (C) 2000 Institut für Telematik, Universität Karlsruhe
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package inet.networklayer.ipv4;

import inet.common.SimpleModule;

//
// ICMP implementation.
//
// @author Jochen Reber
//
simple Icmp extends SimpleModule
{
    parameters:
        @class(Icmp);
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule;
        string checksumMode @mutable @enum("declared", "computed") = default("declared");
        int quoteLength @mutable @unit(B) = default(8B); // Number of bytes from original packet to quote in ICMP reply
        @display("i=block/control");
    gates:
        input transportIn;
        output transportOut;
        input ipIn @labels(Ipv4ControlInfo/up);  // Deliver ICMP packets
        output ipOut @labels(Ipv4ControlInfo/down);  // Towards the network
}
