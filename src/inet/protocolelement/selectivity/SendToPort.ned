//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.protocolelement.selectivity;

import inet.common.SimpleModule;

//
// Adds a destination port header to packets. The header contains the configured
// destination port and is used by the corresponding ReceiveAtPort module to
// filter packets.
//
simple SendToPort extends SimpleModule
{
    parameters:
        @class(SendToPort);
        int port;
        @display("i=block/tx");
    gates:
        input in;
        output out;
}
