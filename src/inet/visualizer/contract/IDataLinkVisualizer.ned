//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.contract;

//
// Interface allows configuring different ~IDataLinkVisualizer
// submodules from INI files. Such a visualizer displays the active data link
// layer links in a network.
//
// @see ~DataLinkCanvasVisualizer, ~DataLinkOsgVisualizer, ~DataLinkVisualizer, ~DataLinkVisualizerBase
//
moduleinterface IDataLinkVisualizer extends IVisualizer
{
    parameters:
        @display("i=block/app");
}

