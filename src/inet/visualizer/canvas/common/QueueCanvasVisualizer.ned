//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.canvas.common;

import inet.visualizer.base.QueueVisualizerBase;
import inet.visualizer.contract.IQueueVisualizer;

//
// Visualizes queues on a 2D canvas.
//
// @see ~QueueOsgVisualizer, ~QueueVisualizer, ~QueueVisualizerBase, ~IQueueVisualizer
//
simple QueueCanvasVisualizer extends QueueVisualizerBase like IQueueVisualizer
{
    parameters:
        double zIndex = default(10); // Determines the drawing order of figures relative to other visualizers
        @class(QueueCanvasVisualizer);
}

