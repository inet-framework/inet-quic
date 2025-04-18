//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.common;

import inet.visualizer.contract.ISceneVisualizer;

//
// Integrates canvas and osg scene visualizers into a single module.
//
// @see ~SceneCanvasVisualizer, ~SceneOsgVisualizer, ~SceneVisualizerBase, ~ISceneVisualizer
//
module SceneVisualizer like ISceneVisualizer
{
    parameters:
        @display("i=block/app");
        string visualizationTargetModule = default("^");
        string visualizationSubjectModule = default("^");
        *.visualizationTargetModule = default(absPath(this.visualizationTargetModule));
        *.visualizationSubjectModule = default(absPath(this.visualizationSubjectModule));
    submodules:
        canvasVisualizer: <default(firstAvailableOrEmpty("SceneCanvasVisualizer"))> like ISceneVisualizer if typename != "" {
            parameters:
                @display("p=100,100");
        }
        osgVisualizer: <default(firstAvailableOrEmpty("SceneOsgVisualizer"))> like ISceneVisualizer if typename != "" {
            parameters:
                @display("p=100,200");
        }
}

