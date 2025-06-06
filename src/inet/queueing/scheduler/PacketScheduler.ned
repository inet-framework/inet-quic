//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.scheduler;

import inet.queueing.base.PacketSchedulerBase;
import inet.queueing.contract.IPacketScheduler;

//
// Connects one packet collector to multiple packet providers. When
// the packet collector pulls a pull packet from it, the scheduler pulls
// a packet from one of its packet providers based
// on the configured scheduler function. The packet scheduler function takes a
// list of packet providers and returns an integer which in turn is used for
// determining the input gate.
//
simple PacketScheduler extends PacketSchedulerBase like IPacketScheduler
{
    parameters:
        string schedulerClass; // Determines the input queue of the packet, the parameter must be the name of a C++ class which implements the IPacketSchedulerFunction interface and is registered via Register_Class
        @class(PacketScheduler);
}
