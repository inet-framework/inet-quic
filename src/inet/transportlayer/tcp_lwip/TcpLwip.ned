//
// Copyright (C) 2010 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.transportlayer.tcp_lwip;

import inet.common.SimpleModule;
import inet.transportlayer.contract.ITcp;

//
// TCP model based on the LWIP 1.3.2 project.
// The original LWIP is available on
// <a href="http://savannah.nongnu.org/projects/lwip/" target="_blank">this page</a>.
//
// See ~ITcp for general TCP layer information.
//
simple TcpLwip extends SimpleModule like ITcp
{
    parameters:
        @class(TcpLwip);
        string sendQueueClass = default("");    //# TODO Obsolete!!!
        string receiveQueueClass = default(""); //# TODO Obsolete!!!
        string checksumMode @enum("declared", "computed") = default("declared");
        @display("i=block/wheelbarrow");

    gates:
        input appIn @messageKinds(inet::TcpCommandCode);
        input ipIn;
        output appOut @messageKinds(inet::TcpStatusInd);
        output ipOut;
}

