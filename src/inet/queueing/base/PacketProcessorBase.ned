//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.queueing.base;

import inet.common.SimpleModule;

//
// Base module for various packet processing modules which maintains
// a few statistics.
//
// Available display string text format directives:
// - %p - number of processed packets
// - %l - total processed packet length
//
simple PacketProcessorBase extends SimpleModule
{
    parameters:
        @class(PacketProcessorBase);
        displayStringTextFormat = default("processed %p pk (%l)"); // Determines the text that is written on top of the submodule
        @display("i=block/star");
}
