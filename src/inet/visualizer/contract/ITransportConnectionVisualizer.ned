//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.contract;

//
// Interface allows configuring different ~ITransportConnectionVisualizer
// submodules from INI files. Such a visualizer displays the active transport
// connections in a network.
//
// @see ~TransportConnectionCanvasVisualizer, ~TransportConnectionOsgVisualizer, ~TransportConnectionVisualizer, ~TransportConnectionVisualizerBase
//
moduleinterface ITransportConnectionVisualizer extends IVisualizer
{
    parameters:
        @display("i=block/app");
}

