//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.base;

import inet.common.SimpleModule;

//
// Base module for visualizer simple modules. It simply provides the
// visualization target module for derived modules.
//
simple VisualizerBase extends SimpleModule
{
    parameters:
        @class(VisualizerBase);
        string visualizationTargetModule = default("^"); // Module path relative to the visualizer which determines where the visualization should appear in the user interface, parent module by default
        string visualizationSubjectModule = default("^"); // Module path relative to the visualizer which determines what part of the simulation model the visualizer displays in the user interface, parent module by default
        string tags = default(""); // Tag added to each visualization for disambiguation in the runtime environment
        @display("i=block/app");
}

