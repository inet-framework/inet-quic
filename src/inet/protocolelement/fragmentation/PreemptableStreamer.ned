//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.protocolelement.fragmentation;

import inet.queueing.base.PacketProcessorBase;
import inet.queueing.contract.IPacketFlow;


//
// Takes packets passed to its input and streams them to its output.
//
simple PreemptableStreamer extends PacketProcessorBase like IPacketFlow
{
    parameters:
        string clockModule = default(""); // Relative path of a module that implements IClock; optional
        double datarate @unit(bps) = default(nan bps);
        int minPacketLength @unit(b);
        int roundingLength @unit(b) = default(1B);
        @class(PreemptableStreamer);
        @display("i=block/cogwheel");
    gates:
        input in @labels(send,push,pull,pass);
        output out @labels(send,push,pull,stream);
}
