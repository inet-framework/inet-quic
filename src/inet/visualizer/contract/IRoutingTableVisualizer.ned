//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.contract;

//
// Interface allows configuring different ~IRoutingTableVisualizer
// submodules from INI files. Such a visualizer displays routes present in the
// routing tables of a network.
//
// @see ~RoutingTableCanvasVisualizer, ~RoutingTableOsgVisualizer, ~RoutingTableVisualizer, ~RoutingTableVisualizerBase
//
moduleinterface IRoutingTableVisualizer extends IVisualizer
{
    parameters:
        @display("i=block/app");
}

