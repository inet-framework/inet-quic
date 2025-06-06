//
// Copyright (C) 2012 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.networklayer.diffserv;

import inet.common.SimpleModule;

//
// Implements a Single Rate Three Color Meter (RFC 2697).
//
// IP packets are classified according to three parameters,
// Committed Information Rate (cir), Committed Burst Size (cbs),
// and Excess Burst Size (ebs), to be either green, yellow, or red.
//
// The green traffic is guaranteed to be under (in bits)
// <pre>
//    cir * (t1 - t0) + 8 * cbs
// </pre>
// and the green+yellow traffic is guaranteed to be under
// <pre>
//    cir * (t1 - t0) + 8 * (cbs + ebs)
// </pre>
// in every [t0,t1] interval.
//
// When operating in color-aware mode, the meter does not recolor
// a packet that was colored by a previous marker to a lesser conforming color.
//
simple SingleRateThreeColorMeter extends SimpleModule
{
    parameters:
        @class(SingleRateThreeColorMeter);
        @display("i=block/timer");
        string interfaceTableModule;   // The path to the InterfaceTable module
        string cir;       // Committed information rate, either absolute bitrate (e.g. "100kbps") or relative to the link's datarate (e.g. "20%")
        int cbs @unit(B); // Committed burst size
        int ebs @unit(B); // Excess burst size
        bool colorAwareMode = default(false); // Enables color-aware mode
    gates:
        input in;
        output greenOut;
        output yellowOut;
        output redOut;
}

