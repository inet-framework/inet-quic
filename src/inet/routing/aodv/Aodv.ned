//
// Copyright (C) 2014 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.routing.aodv;

import inet.common.SimpleModule;
import inet.applications.contract.IApp;

//
// Ad hoc On-Demand Distance Vector Routing Protocol module.
//
// The Ad hoc On-Demand Distance Vector (AODV) routing protocol is
// intended for use by mobile nodes in an ad hoc network. It offers
// quick adaptation to dynamic link conditions, low processing and
// memory overhead, low network utilization, and determines unicast
// routes to destinations within the ad hoc network.
//
// This routing protocol communicates over UDP and is used in ~AodvRouter
// nodes as a routing submodule. ~AodvRouter is just a ~WirelessHost
// extended with an ~Aodv submodule.
//
// This implementation is based on RFC 3561. For more information, you may
// refer to the following link: https://tools.ietf.org/html/rfc3561.html.
//
simple Aodv extends SimpleModule like IApp
{
    parameters:
        @class(aodv::Aodv);
        @display("i=block/network2");
        string routingTableModule = default("^.ipv4.routingTable");
        string interfaceTableModule = default("^.interfaceTable");
        string networkProtocolModule = default("^.ipv4.ip");
        bool askGratuitousRREP = default(false); // See RFC 3561: 6.6.3
        bool useHelloMessages = default(false); // See RFC 3561: 6.9
        bool useLocalRepair = default(false); // See RFC 3561: 6.12 *not implemented yet*
        bool destinationOnlyFlag = default(false); // See RFC 3561: 5.1
        int udpPort = default(654);
        string interface = default("wlan0");

        double maxPeriodicJitter @unit(s) = default(helloInterval / 4); // It MUST NOT be negative; it MUST NOT be greater than MESSAGE_INTERVAL/2; it SHOULD NOT be greater than MESSAGE_INTERVAL/4.
        volatile double periodicJitter @unit(s) = default(uniform(0s, maxPeriodicJitter)); // Jitter for externally triggered message generation and message forwarding

        // RFC 5148:
        // need more revision: As well as the decision as to whether
        // to use jitter being dependent on the medium access control and
        // lower layers, the selection of the MAXJITTER parameter SHOULD
        // be appropriate to those mechanisms.
        double maxJitter @unit(s) = default(5ms);
        volatile double jitter @unit(s) = default(uniform(0ms, maxJitter)); // Jitter for broadcasts

        double helloInterval @unit(s) = default(1s); // Every helloInterval seconds a node broadcasts Hello messages (if it is necessary)
        int allowedHelloLoss = default(2); // AllowedHelloLoss * helloInterval is the lifetime value for Hello messages
        double activeRouteTimeout @unit(s) = default(3s); // The timeout value for cached routes. If Hello messages are used, then the
                                                            // ACTIVE_ROUTE_TIMEOUT parameter value MUST be more than the value
                                                            // (ALLOWED_HELLO_LOSS * HELLO_INTERVAL).
        int netDiameter = default(35); // The maximum possible number of hops between two nodes in the network
        double nodeTraversalTime @unit(s) = default(0.04s); // An estimation of the average one-hop traversal time
        int rerrRatelimit = default(10); // Maximum number of RERR messages that the AODV may originate in 1s.
        int rreqRetries = default(2); // Specifies the number of times AODV will repeat an expanded ring search for a destination
        int rreqRatelimit = default(10); // Maximum number of RREQ messages that the AODV may originate in 1s.
        int timeoutBuffer = default(2); // Plus time to wait for a delayed RREP (due to congestion) (to omit this buffer set it to 0)
        int ttlStart = default(2); // Specifies the TTL value when initiating a route request
        int ttlIncrement = default(2); // Specifies the value by which the TTL will be incremented each time a RREQ is retransmitted
        int ttlThreshold = default(7); // The maximum value of TTL over which NET_DIAMETER value will be used to broadcast any RREQ
        int localAddTTL = default(2); // It is used by the formula which calculates the initial TTL of the RREQ for a local repair

        double myRouteTimeout @unit(s) = default(2 * activeRouteTimeout); // The value of the lifetime field that a destination node places in RREPs
        double deletePeriod @unit(s) = default(5 * max(activeRouteTimeout, helloInterval)); // The time after which an expired route is deleted
        double blacklistTimeout @unit(s) = default(rreqRetries * netTraversalTime); // The time after which a blacklisted node is removed from the blacklist
        double netTraversalTime @unit(s) = default(2 * nodeTraversalTime * netDiameter); // An estimation of the traversal time for the complete network
        double nextHopWait @unit(s) = default(nodeTraversalTime + 0.01s); // Timeout for a RREP-ACK
        double pathDiscoveryTime @unit(s) = default(2 * netTraversalTime); // Buffer timeout for each broadcasted RREQ message
    gates:
        input socketIn;
        output socketOut;
}

