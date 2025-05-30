//
// Copyright (C) 2013 Brno University of Technology (http://nes.fit.vutbr.cz/ansa)
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

// Authors: Veronika Rybova, Vladimir Vesely (ivesely@fit.vutbr.cz),
//          Tamas Borbely (tomi@omnetpp.org)

package inet.routing.pim;

import inet.common.SimpleModule;

//
// ~PimSplitter module dispatches PIM packets received from the network layer
// according to the PIM mode of the incoming interface. By using a ~PimSplitter
// it is possible to build nodes that operate in Dense Mode on some interfaces,
// and in Sparse Mode on others.
//
// See ~Pim module for example usage.
//
simple PimSplitter extends SimpleModule
{
    parameters:
        @class(PimSplitter);
        @display("i=block/dispatch");
        string interfaceTableModule;
        string pimInterfaceTableModule;

    gates:
        input ipIn;
        output ipOut;
        input pimDMIn;
        output pimDMOut;
        input pimSMIn;
        output pimSMOut;
}

