//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.osg.scene;

import inet.visualizer.base.NetworkConnectionVisualizerBase;
import inet.visualizer.contract.INetworkConnectionVisualizer;

//
// Visualizes multiple network connections on a 3D OSG scene.
//
// @see ~NetworkConnectionCanvasVisualizer, ~NetworkConnectionVisualizer, ~NetworkConnectionVisualizerBase, ~INetworkConnectionVisualizer
//
simple NetworkConnectionOsgVisualizer extends NetworkConnectionVisualizerBase like INetworkConnectionVisualizer
{
    parameters:
        @class(NetworkConnectionOsgVisualizer);
}

