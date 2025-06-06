//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.IStatisticVisualizer;

//
// Integrates canvas and osg statistic visualizers into a single module.
//
// @see ~StatisticCanvasVisualizer, ~StatisticOsgVisualizer, ~StatisticVisualizerBase, ~IStatisticVisualizer
//
module StatisticVisualizer like IStatisticVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("StatisticCanvasVisualizer"))> like IStatisticVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("StatisticOsgVisualizer"))> like IStatisticVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

