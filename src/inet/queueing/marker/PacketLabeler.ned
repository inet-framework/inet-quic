//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.marker;

import inet.queueing.base.PacketMarkerBase;
import inet.queueing.contract.IPacketMarker;

//
// Attaches a ~LabelsTag to packets based on the configured filters.
// For each matching filter, a new label is attached.
//
simple PacketLabeler extends PacketMarkerBase like IPacketMarker
{
    parameters:
        string filterClasses = default(""); // Determines the packets that are marked. The parameter must be the name of a C++ class that implements the IPacketFilterFunction interface and is registered via Register_Class.
        string labels = default(""); // A space-separated list of labels.
        @display("i=block/star");
        @class(PacketLabeler);
}
