//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.ILinkBreakVisualizer;

//
// Integrates canvas and osg link break visualizers into a single module.
//
// @see ~LinkBreakCanvasVisualizer, ~LinkBreakOsgVisualizer, ~LinkBreakVisualizerBase, ~ILinkBreakVisualizer
//
module LinkBreakVisualizer like ILinkBreakVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("LinkBreakCanvasVisualizer"))> like ILinkBreakVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("LinkBreakOsgVisualizer"))> like ILinkBreakVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

