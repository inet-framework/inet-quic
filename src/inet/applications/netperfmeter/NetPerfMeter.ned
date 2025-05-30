// * --------------------------------------------------------------------------
// *
// *     //====//  //===== <===//===>  //====//
// *    //        //          //      //    //    SCTP Optimization Project
// *   //=====   //          //      //====//   ==============================
// *        //  //          //      //           University of Duisburg-Essen
// *  =====//  //=====     //      //
// *
// * --------------------------------------------------------------------------
// *
//
// Copyright (C) 2009-2015 by Thomas Dreibholz <dreibh@iem.uni-due.de>
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.applications.netperfmeter;

import inet.common.SimpleModule;
import inet.applications.contract.IApp;

//
// Application model for comparing the performance of various transport
// protocols.
//
// The ~NetPerfMeter model simultaneously transmits bidirectional flows to an
// endpoint, and measures the resulting flow bandwidths and QoS. Since the
// application behavior is the same for all underlying transport layer
// protocols, it allows for comparing the performance of various transport
// protocols, e.g. TCP vs. SCTP.
//
// The model closely mimics the operation of the real-world NetPerfMeter
// application (https://www.uni-due.de/~~be0001/netperfmeter/), a tool for
// measuring UDP, TCP, MPTCP, SCTP and DCCP performance over IPv4 and IPv6.
// Since the parametrization and features are similar to the real-world
// application, the model also makes comparisons of simulation results and
// real-world measurements easy.
//
simple NetPerfMeter extends SimpleModule like IApp
{
    parameters:
        @class(NetPerfMeter);
        bool            activeMode               = default(true);      // Server (false) or client (true)
        string          localAddress             = default("");        // May be left empty ("")
        int             localPort                = default(9000);      // Port number to listen on
        string          remoteAddress            = default("");        // Server address (may be symbolic)
        int             remotePort               = default(9000);      // Port number to connect to

        double          connectTime     @unit(s) = default(0s);        // Absolute time to establish connection
        double          startTime       @unit(s) = default(1s);        // Transmission start, relative to "connectTime"
        double          resetTime       @unit(s) = default(5s);        // Statistics reset, relative to "connectTime"
        double          stopTime        @unit(s) = default(30s);       // Transmission stop, relative to "resetTime"
        int             queueSize       @unit(B) = default(1000000 B); // Size of the transmission queue (SCTP/TCP only)

        double          onTime          @unit(s) = default(-1s);       // Online time; disconnect when timer expires
        double          offTime         @unit(s) = default(-1s);       // Offline time; reconnect when timer expires
        int             maxOnOffCycles           = default(0);         // Maximum number of on-off cycles (-1 for unlimited)

        int             outboundStreams          = default(1);         // Number of outbound streams (SCTP only)
        int             maxInboundStreams        = default(16);        // Maximum number of inbound streams (SCTP only)
        string          protocol                 = default("SCTP");    // Transport protocol to use
        string          primaryPath              = default("");        // Primary path (may be symbolic; SCTP only)

        volatile double frameRate      @unit(Hz) = default(1 Hz);      // Outgoing frame rate
        volatile int    frameSize      @unit(B)  = default(1452 B);    // Outgoing frame size
        string          frameRateString          = default("");        // Outgoing frame rate per stream, separated by ";"
        string          frameSizeString          = default("");        // Outgoing frame size per stream, separated by ";"
        string          traceFile                = default("");        // Use trace file instead of frame rate/frame size
        int             maxMsgSize     @unit(B)  = default(1000 B);    // Maximum message size
        double          unordered                = default(0.0);       // Fraction of unordered messages (SCTP only)
        double          unreliable               = default(0.0);       // Fraction of unreliable messages (SCTP only)
        bool            decoupleSaturatedStreams = default(true);      // Apply buffer splitting when using multiple streams

    gates:
        input socketIn;
        output socketOut;
}

