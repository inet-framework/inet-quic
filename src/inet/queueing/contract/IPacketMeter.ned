//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.contract;

//
// Interface for packet meter modules. A packet meter
// connects one input to one output. It can operate in both active and passive
// mode. Packets can be pushed into its input or packets can be pulled from its
// output. When processing packets, a meter attaches some information (such as
// the packet rate) to the packets based on the data and metadata they contain.
// The packets are processed as part of a stream.
//
moduleinterface IPacketMeter extends IPacketFlow
{
    parameters:
        @omittedTypename(OmittedPacketMeter);
        @display("i=block/star");
}
