//
// Copyright (C) 2006 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.linklayer.ieee80211.mgmt;

import inet.common.SimpleModule;

//
// Used in 802.11 infrastructure mode in an access point (AP).
//
// This module expects ~Ieee80211MgmtSta modules to be present in the stations.
//
// This module never switches channels, that is, it will operate on the channel
// the physical layer is configured for (see `channelNumber` in ~Ieee80211Radio).
//
// This module relies on a connected ~Ieee80211Mac for actual
// reception and transmission of frames.
//
simple Ieee80211MgmtAp extends SimpleModule like IIeee80211Mgmt
{
    parameters:
        @class(Ieee80211MgmtAp);
        string ssid = default("SSID");
        double beaconInterval @unit(s) = default(100ms);
        int numAuthSteps = default(4); // Use 2 for Open System auth, 4 for WEP
        string interfaceTableModule;
        string radioModule = default("^.radio");   // The path to the Radio module  //FIXME remove default value
        string mibModule;
        string macModule;               // The path to the MAC module
        @display("i=block/cogwheel");
        @signal[l2ApAssociated](type="inet::ieee80211::Ieee80211MgmtAp::NotificationInfoSta");
        @signal[l2ApDisassociated](type="inet::ieee80211::Ieee80211MgmtAp::NotificationInfoSta");
    gates:
        input macIn @labels(Ieee80211MacHeader); // From ~Ieee80211Mac
        output macOut @labels(Ieee80211MacHeader); // To ~Ieee80211Mac
        input agentIn @loose;   // Unused dummy to satisfy the IIeee80211Mgmt interface
        output agentOut @loose; // Unused dummy to satisfy the IIeee80211Mgmt interface
}
