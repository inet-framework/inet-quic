//
// Copyright (C) 2005 Vojtech Janota
// Copyright (C) 2003 Xuan Thang Nguyen
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#ifndef __INET_LIBTABLE_H
#define __INET_LIBTABLE_H

#include "inet/common/SimpleModule.h"
#include <string>
#include <vector>

#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/mpls/ConstType.h"

namespace inet {

enum LabelOpCode {
    PUSH_OPER,
    SWAP_OPER,
    POP_OPER
};

struct LabelOp
{
    int label;
    LabelOpCode optcode;
};

typedef std::vector<LabelOp> LabelOpVector;

/**
 * Represents the Label Information Base (LIB) for MPLS.
 */
class INET_API LibTable : public SimpleModule
{
  public:
    struct LibEntry {
        int inLabel;
        std::string inInterface;

        LabelOpVector outLabel;
        std::string outInterface;

        // FIXME colors in nam, temporary solution
        int color;
    };

  protected:
    int maxLabel;
    std::vector<LibEntry> lib;

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void handleMessage(cMessage *msg) override;

    // static configuration
    virtual void readTableFromXML(const cXMLElement *libtable);

  public:
    // label management
    virtual bool resolveLabel(std::string inInterface, int inLabel,
            LabelOpVector& outLabel, std::string& outInterface, int& color);

    virtual int installLibEntry(int inLabel, std::string inInterface, const LabelOpVector& outLabel,
            std::string outInterface, int color);

    virtual void removeLibEntry(int inLabel);

    // utility
    static LabelOpVector pushLabel(int label);
    static LabelOpVector swapLabel(int label);
    static LabelOpVector popLabel();
};

std::ostream& operator<<(std::ostream& os, const LibTable::LibEntry& lib);
std::ostream& operator<<(std::ostream& os, const LabelOpVector& label);

} // namespace inet

#endif

