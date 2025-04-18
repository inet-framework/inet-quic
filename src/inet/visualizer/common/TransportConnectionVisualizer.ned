//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.ITransportConnectionVisualizer;

//
// Integrates canvas and osg transport connection visualizers into a single module.
//
// @see ~TransportConnectionCanvasVisualizer, ~TransportConnectionOsgVisualizer, ~TransportConnectionVisualizerBase, ~ITransportConnectionVisualizer
//
module TransportConnectionVisualizer like ITransportConnectionVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("TransportConnectionCanvasVisualizer"))> like ITransportConnectionVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("TransportConnectionOsgVisualizer"))> like ITransportConnectionVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

