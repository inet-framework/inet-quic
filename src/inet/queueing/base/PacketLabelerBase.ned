//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.base;

//
// Base module for various packet labeler modules.
//
simple PacketLabelerBase extends PacketMarkerBase
{
    parameters:
        string labels = default(""); // A space-separated list of labels
        @class(PacketLabelerBase);
        @display("i=block/star");
}
