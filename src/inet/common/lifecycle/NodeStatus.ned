//
// Copyright (C) 2013 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.common.lifecycle;

import inet.common.SimpleModule;

//
// Keeps track of the status of the network node (up, down, etc.) for other
// modules, and also displays it as a small overlay icon on this module
// and on the module of the network node.
//
simple NodeStatus extends SimpleModule
{
    parameters:
        @class(NodeStatus);
        //TODO @signal, @statistic
        string initialStatus = default("UP"); // Initial status of the network node
        @display("i=block/cogwheel;is=s");
        @signal[nodeStatusChanged](type=inet::NodeStatus);
}

