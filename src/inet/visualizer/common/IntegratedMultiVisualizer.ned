//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.IIntegratedVisualizer;

//
// Integrates canvas and osg visualizers into a single module.
//
module IntegratedMultiVisualizer like IIntegratedVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.*.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.*.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("IntegratedMultiCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("IntegratedMultiOsgVisualizer"))> like IIntegratedVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

