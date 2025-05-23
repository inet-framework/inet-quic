//
// Copyright (C) 2005 M. Bohge (bohge@tkn.tu-berlin.de), M. Renwanz
// Copyright (C) 2010 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package inet.applications.voipstream;

import inet.common.SimpleModule;
import inet.applications.contract.IApp;

//
// VoipStreamReceiver listens on a UDP port and expects to receive VoIP packets on
// it. The received voice is then saved into a result audio file that can be
// compared with the original for further evaluation. VoIP packets are
// numbered, and out-of-order packets are discarded (the corresponding voice
// interval will be recorded as silence into the file). VoIP packets that miss
// their deadlines will similarly be discarded. It is assumed that the audio is
// played back with a delay (by default 20ms), which allows some jitter for the
// incoming packets. The resulting audio file is closed when the simulation
// completes (i.e., in the OMNeT++ finish() function). Only one voice session
// ("call") may be underway at a time.
//
simple VoipStreamReceiver extends SimpleModule like IApp
{
    parameters:
        @class(VoipStreamReceiver);
        int localPort;
        double playoutDelay @unit(s) = default(20ms);
        string resultFile;
        @signal[packetReceived](type=inet::Packet); // Expected type=VoipStreamPacket
        @signal[packetDropped](type=inet::Packet);
        @signal[lostSamples](type=long);
        @signal[lostPackets](type=long);
        @signal[packetHasVoice](type=long);  // 1=yes, 0=no
        @signal[connState](type=long);  // 1=open, -1=close
        @signal[delay](type=simtime_t);  // Total time lag of voice transmission
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[dropPk](title="packets dropped"; source=packetDropped; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[lostSamples](title="lost samples"; interpolationmode=none; record=vector,stats);
        @statistic[lostPackets](title="lost packets"; interpolationmode=none; record=vector,stats);
        @statistic[packetHasVoice](title="voice or silence packet"; record=mean,vector; interpolationmode=none);
        @statistic[delay](title="delay"; unit=s; record=vector,histogram; interpolationmode=none);
        @statistic[numActiveSessions](title="number of active sessions"; source=warmup(sum(connState)); record=max,timeavg,vector; interpolationmode=sample-hold; autoWarmupFilter=false);
        @statistic[numSessions](title="total number of sessions"; source="sum(connState+1)/2"; record=last);
        @display("i=block/arrival");
    gates:
        input socketIn @labels(UdpCommand/up);
        output socketOut @labels(UdpCommand/down);
}

