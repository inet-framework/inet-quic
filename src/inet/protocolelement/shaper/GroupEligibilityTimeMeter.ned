//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package inet.protocolelement.shaper;

//
// Extends the `EligibilityTimeMeter` with scheduler groups.
// The calculation of the eligibility time takes into account the eligibility times of all
// streams of the same group.
//
// This module is part of the asynchronous shaper infrastructure.
//
// @see ~ATS8021qFilter, ~EligibilityTimeGate, ~EligibilityTimeFilter, ~EligibilityTimeQueue, ~EligibilityTimeTag
//

simple GroupEligibilityTimeMeter extends EligibilityTimeMeter
{
	parameters:
        string groupEligibilityTimeTableModule; // Relative path to the eligibilityTimeTable
        @class(GroupEligibilityTimeMeter);
}