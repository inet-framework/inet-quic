//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.linklayer.configurator.common;

import inet.common.SimpleModule;
import inet.networklayer.configurator.contract.INetworkConfigurator;

//
// Configures the forwarding database (MAC address table) of all
// network nodes in the network based on the automatically discovered network
// topology. The configurator uses the shortest path algorithm to determine the
// outgoing network interface for all network nodes and all destination network
// interfaces. The effect of this configuration is that the network can use the
// the ~GlobalArp module and completely eliminate the ARP protocol messages.
//
// @see ~MacForwardingTable
//
simple MacForwardingTableConfigurator extends SimpleModule like INetworkConfigurator
{
    parameters:
        @class(MacForwardingTableConfigurator);
        @display("i=block/cogwheel");
}

