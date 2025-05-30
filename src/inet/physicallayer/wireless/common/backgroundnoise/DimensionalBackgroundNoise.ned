//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.physicallayer.wireless.common.backgroundnoise;

import inet.common.Module;
import inet.physicallayer.wireless.common.contract.packetlevel.IBackgroundNoise;

//
// Background noise model for wireless communications that represents ambient
// noise as a power spectral density function of time and frequency.
// Supports configurable time-varying and frequency-varying gain patterns
// with various interpolation methods. Used to model realistic noise
// conditions in wireless channel simulations.
//
module DimensionalBackgroundNoise extends Module like IBackgroundNoise
{
    parameters:
        int gainFunctionCacheLimit = default(0); // Limits the number of gain functions cached for a given duration, centerFrequency and bandwidth
        string timeGains = default("left 0s 0dB left"); // Sequence of interpolation methods, time, gain tuples; time can be an expression, gain is in [dB] or [0..inf); default value is a flat signal
        string timeGainsNormalization @enum("", "maximum", "integral") = default(""); // Determines how the time gains function is normalized, no normalization by default
        string frequencyGains = default("left 0Hz 0dB left"); // Sequence of interpolation methods, frequency, gain tuples; frequency can be an expression, gain is in [dB] or [0..1]; default value is a flat signal
        string frequencyGainsNormalization @enum("", "maximum", "integral") = default("integral"); // Determines how the frequency gains function is normalized, integral normalization by default
        double power @unit(dBm); // Noise power
        @class(DimensionalBackgroundNoise);
        @display("i=block/mac");
}

