//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.filter;

import inet.common.Module;
import inet.queueing.contract.IPacketFilter;

//
// Implements the given module interface and can be used as an omitted
// optional module that removes itself from the module hierarchy during initialization.
//
module OmittedPacketFilter extends Module like IPacketFilter
{
    parameters:
        @class(::inet::OmittedModule);
        @display("i=block/star,black,50");
    gates:
        input in;
        output out;
    connections:
        in --> out;
}

