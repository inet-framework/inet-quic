//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.visualizer.base;

//
// Base module for radio visualizer simple modules.
//
// @see ~RadioCanvasVisualizer, ~RadioOsgVisualizer, ~IRadioVisualizer, ~VisualizerBase
//
simple RadioVisualizerBase extends VisualizerBase
{
    parameters:
        string networkNodeVisualizerModule = default("^.networkNodeVisualizer"); // Module path to the network node visualizer module, refers to a sibling submodule by default

        bool displayRadios = default(false);
        bool displayRadioMode = default(true);
        bool displayReceptionState = default(true);
        bool displayTransmissionState = default(true);
        bool displayAntennaLobes = default(false);

        string radioFilter @mutable = default("**"); // Which radios are considered, matches all radios by default

        string radioModeImages = default("block/process_vs block/timer_vs block/wrx_vs block/wtx_vs block/wrxtx_vs block/cogwheel_vs");
        string receptionStateImages = default("- - misc/receiving misc/receiving");
        string transmissionStateImages = default("- - misc/transmitting");
        double width = default(16);
        double height = default(16);
        string placementHint = default("bottomRight"); // Annotation placement hint, space separated list of any, top, bottom, left, right, topLeft, topCenter, topRight, etc.
        double placementPriority = default(0); // Determines the order of annotation positioning

        bool antennaLobeNormalize = default(false); // True means maximum gain, false means 0dB is displayed at the given antennaLobeRadius
        bool antennaLobeRelativeLabels = default(false); // Determines whether gain labels are relative or absolute (if true, maximum gain label is 0dB)
        bool antennaLobePlaneGlobal = default(true); // Compute antenna lobe relative to the global or antenna local coordinate systems, global by default
        string antennaLobePlane @enum("view", "xy", "xz", "yz") = default("view"); // Compute antenna lobe in this plane, view by default
        string antennaLobeMode @enum("logarithmic", "linear") = default("logarithmic");
        double antennaLobeLogarithmicBase = default(10);
        double antennaLobeLogarithmicScale = default(100); // Distance change in pixels for 10dB
        double antennaLobeRadius = default(100); // Distance in pixels for 0dB (1 gain) or maximum gain depending on antennaLobeNormalize parameter
        double antennaLobeStep @unit(deg) = default(10deg);
        double antennaLobeOpacity = default(0.25); // Opacity of the antenna lobe
        bool antennaLobeLineSmooth = default(true);
        string antennaLobeLineColor = default("black"); // Antenna lobe line color, black by default
        string antennaLobeLineStyle = default("solid"); // Antenna lobe line style (solid, dashed, dotted)
        double antennaLobeLineWidth = default(1); // Antenna lobe line width
        string antennaLobeFillColor = default("white"); // Antenna lobe fill color, white by default

        @class(RadioVisualizerBase);
}

