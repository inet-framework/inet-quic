//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.linklayer.ieee8021q;

import inet.common.Module;
//
// Implements the module given interface and can be used as an omitted
// optional module that removes itself from the module hierarchy during initialize.
//
module OmittedIeee8021qTagTpidHeaderChecker extends Module like IIeee8021qTagTpidHeaderChecker
{
    parameters:
        string vlanTagType = default("");
        @class(::inet::OmittedModule);
        @display("i=block/checker,black,50");
    gates:
        input in;
        output out;
    connections:
        in --> out;
}

