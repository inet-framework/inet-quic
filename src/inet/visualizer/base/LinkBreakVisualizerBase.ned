//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.base;

//
// Base module for link break visualizer simple modules. It keeps
// track of link breaks in a network. Link breaks are not displayed by
// default, see module parameters for how to enable the visualization. The
// actual visualization of link breaks is done in derived modules.
//
// This module subscribes to `linkBroken` on the module determined by the
// `visualizationSubjectModule` parameter. If the visualizer receives a link break signal,
// then it stores the broken link and starts the link break visualization.
//
// @see ~LinkBreakCanvasVisualizer, ~LinkBreakOsgVisualizer, ~ILinkBreakVisualizer, ~VisualizerBase
//
simple LinkBreakVisualizerBase extends VisualizerBase
{
    parameters:
        bool displayLinkBreaks = default(false); // Display icons for link breaks, disabled by default

        string nodeFilter @mutable = default("*"); // Which network nodes are considered, matches all nodes by default
        string interfaceFilter @mutable = default("*"); // Which interfaces are considered, matches all interfaces by default
        object packetFilter @mutable = default("*"); // Which packets are considered, matches all packets by default

        string icon = default("status/stop");
        double iconTintAmount = default(0);
        string iconTintColor = default("");

        string fadeOutMode @enum("realTime", "animationTime", "simulationTime") = default("realTime"); // Specifies how inactive link breaks fade out
        double fadeOutTime @unit(s) = default(1s); // How quickly link breaks fade away, 1 second by default
        double fadeOutAnimationSpeed = default(0); // Animation speed while there are link breaks, value must be in the range (0, +inf)

        @class(LinkBreakVisualizerBase);
}

