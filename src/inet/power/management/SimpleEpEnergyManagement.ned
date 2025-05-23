//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.power.management;

import inet.common.SimpleModule;
import inet.power.contract.IEpEnergyManagement;

//
// This energy management model estimates the residual energy capacity of the
// energy source model by actually querying it. It is only useful when the
// estimation process is not important. This model initiates node shutdown
// when the residual capacity decreases below a threshold, and it also
// initiates node start when the residual capacity increases above another
// threshold.
//
// @see ~SimpleEpEnergyStorage
//
simple SimpleEpEnergyManagement extends SimpleModule like IEpEnergyManagement
{
    parameters:
        @class(SimpleEpEnergyManagement);
        double nodeShutdownCapacity @unit(J) = default(nan J); // Initiates node shutdown when the residual energy capacity decreases below this value
        double nodeStartCapacity @unit(J) = default(nan J); // Initiates node start when the residual energy capacity increases above this value
        @class(SimpleEpEnergyManagement);
        @display("i=block/plug");
}

