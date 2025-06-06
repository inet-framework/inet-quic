//
// Copyright (C) 2013 Brno University of Technology (http://nes.fit.vutbr.cz/ansa)
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

// Authors: Veronika Rybova, Vladimir Vesely (ivesely@fit.vutbr.cz),
//          Tamas Borbely (tomi@omnetpp.org)

#include "inet/routing/pim/tables/PimNeighborTable.h"

#include "inet/common/stlutils.h"

namespace inet {

Register_Abstract_Class(PimNeighbor);
Define_Module(PimNeighborTable);

PimNeighbor::PimNeighbor(NetworkInterface *ie, Ipv4Address address, int version)
    : nt(nullptr), ie(ie), address(address), version(version), generationId(0), drPriority(-1L)
{
    ASSERT(ie);

    livenessTimer = new cMessage("NeighborLivenessTimer", PimNeighborTable::NeighborLivenessTimer);
    livenessTimer->setContextPointer(this);
}

PimNeighbor::~PimNeighbor()
{
    delete livenessTimer;
}

// for WATCH_MAP()
std::ostream& operator<<(std::ostream& os, const PimNeighborTable::PimNeighborVector& v)
{
    for (unsigned int i = 0; i < v.size(); i++) {
        PimNeighbor *e = v[i];
        os << "[" << i << "]: "
           << "{ If: " << e->getInterfacePtr()->getInterfaceName() << " Addr: " << e->getAddress() << " Ver: " << e->getVersion()
           << " GenID: " << e->getGenerationId() << " DrPriority: " << e->getDRPriority() << " livenessTimer: " << e->getLivenessTimer()->getArrivalTime() << " }; ";
    }
    return os;
};

std::string PimNeighbor::str() const
{
    std::stringstream out;
    out << "PimNeighbor addr=" << address << ", iface=" << ie->getInterfaceName() << ", v=" << version << ", priority=" << this->drPriority << "}";
    return out.str();
}

void PimNeighbor::changed()
{
    if (nt)
        nt->emit(pimNeighborChangedSignal, this);
}

PimNeighborTable::~PimNeighborTable()
{
    for (auto& elem : neighbors) {
        for (auto& _it2 : elem.second) {
            cancelEvent((_it2)->getLivenessTimer());
            delete _it2;
        }
    }
}

void PimNeighborTable::initialize(int stage)
{
    SimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        WATCH_MAP(neighbors);
    }
}

void PimNeighborTable::handleMessage(cMessage *msg)
{
    // self message (timer)
    if (msg->isSelfMessage()) {
        if (msg->getKind() == NeighborLivenessTimer) {
            processLivenessTimer(msg);
        }
        else
            ASSERT(false);
    }
    else
        throw cRuntimeError("PimNeighborTable received a message although it does not have gates.");
}

void PimNeighborTable::processLivenessTimer(cMessage *livenessTimer)
{
    EV << "PimNeighborTable::processNLTimer\n";
    PimNeighbor *neighbor = check_and_cast<PimNeighbor *>((cObject *)livenessTimer->getContextPointer());
    Ipv4Address neighborAddress = neighbor->getAddress();
    deleteNeighbor(neighbor);
    EV << "PIM::processNLTimer: Neighbor " << neighborAddress << "was removed from PIM neighbor table.\n";
}

bool PimNeighborTable::addNeighbor(PimNeighbor *entry, double holdTime)
{
    Enter_Method("addNeighbor");

    PimNeighborVector& neighborsOnInterface = neighbors[entry->getInterfaceId()];

    for (auto& elem : neighborsOnInterface)
        if ((elem)->getAddress() == entry->getAddress())
            return false;

    EV_DETAIL << "Added new neighbor to table: " << entry->str() << "\n";
    entry->nt = this;
    neighborsOnInterface.push_back(entry);
    take(entry->getLivenessTimer());
    restartLivenessTimer(entry, holdTime);

    emit(pimNeighborAddedSignal, entry);

    return true;
}

bool PimNeighborTable::deleteNeighbor(PimNeighbor *neighbor)
{
    Enter_Method("deleteNeighbor");

    auto it = neighbors.find(neighbor->getInterfaceId());
    if (it != neighbors.end()) {
        PimNeighborVector& neighborsOnInterface = it->second;
        auto it2 = find(neighborsOnInterface, neighbor);
        if (it2 != neighborsOnInterface.end()) {
            neighborsOnInterface.erase(it2);

            emit(pimNeighborDeletedSignal, neighbor);

            neighbor->nt = nullptr;
            cancelEvent(neighbor->getLivenessTimer());
            delete neighbor;

            return true;
        }
    }
    return false;
}

void PimNeighborTable::restartLivenessTimer(PimNeighbor *neighbor, double holdTime)
{
    Enter_Method("restartLivenessTimer");
    rescheduleAfter(holdTime, neighbor->getLivenessTimer());
}

PimNeighbor *PimNeighborTable::findNeighbor(int interfaceId, Ipv4Address addr)
{
    auto neighborsOnInterface = neighbors.find(interfaceId);
    if (neighborsOnInterface != neighbors.end()) {
        for (auto& elem : neighborsOnInterface->second)
            if ((elem)->getAddress() == addr && (elem)->getInterfaceId() == interfaceId)
                return elem;

    }
    return nullptr;
}

int PimNeighborTable::getNumNeighbors(int interfaceId)
{
    auto it = neighbors.find(interfaceId);
    return it != neighbors.end() ? it->second.size() : 0;
}

PimNeighbor *PimNeighborTable::getNeighbor(int interfaceId, int index)
{
    auto it = neighbors.find(interfaceId);
    return it != neighbors.end() ? it->second.at(index) : nullptr;
}

} // namespace inet

