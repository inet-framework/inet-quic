//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.linklayer.configurator.gatescheduling.common;

import inet.linklayer.configurator.gatescheduling.base.GateScheduleConfiguratorBase;
import inet.linklayer.configurator.gatescheduling.contract.IGateScheduleConfigurator;

//
// Provides a trivial gate scheduling algorithm that keeps all gates
// in the network open all the time.
//
simple AlwaysOpenGateScheduleConfigurator extends GateScheduleConfiguratorBase like IGateScheduleConfigurator
{
    parameters:
        @class(AlwaysOpenGateScheduleConfigurator);
}

