//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.INetworkRouteVisualizer;

//
// Integrates canvas and osg network route visualizers into a single module.
//
// @see ~NetworkRouteCanvasVisualizer, ~NetworkRouteOsgVisualizer, ~PathVisualizerBase, ~INetworkRouteVisualizer
//
module NetworkRouteVisualizer like INetworkRouteVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("NetworkRouteCanvasVisualizer"))> like INetworkRouteVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("NetworkRouteOsgVisualizer"))> like INetworkRouteVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

