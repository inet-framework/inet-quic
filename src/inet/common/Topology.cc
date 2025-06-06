//
// Copyright (C) 1992-2012 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include "inet/common/Topology.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <deque>
#include <list>
#include <sstream>

#include "inet/common/PatternMatcher.h"
#include "inet/common/stlutils.h"

namespace inet {

Register_Class(Topology);

Topology::Link *Topology::Node::getLinkIn(int i) const
{
    if (i < 0 || i >= (int)inLinks.size())
        throw cRuntimeError("Topology::Node::getLinkIn: invalid link index %d", i);
    return inLinks[i];
}

Topology::Link *Topology::Node::getLinkOut(int i) const
{
    if (i < 0 || i >= (int)outLinks.size())
        throw cRuntimeError("Topology::Node::getLinkOut: invalid index %d", i);
    return outLinks[i];
}

// ----

Topology::Topology(const char *name) : cOwnedObject(name)
{
}

Topology::Topology(const Topology& topo) : cOwnedObject(topo)
{
    throw cRuntimeError(this, "copy ctor not implemented yet");
}

Topology::~Topology()
{
    clear();
}

std::string Topology::str() const
{
    std::stringstream out;
    out << "n=" << nodes.size();
    return out.str();
}

void Topology::parsimPack(cCommBuffer *buffer) const
{
    throw cRuntimeError(this, "parsimPack() not implemented");
}

void Topology::parsimUnpack(cCommBuffer *buffer)
{
    throw cRuntimeError(this, "parsimUnpack() not implemented");
}

Topology& Topology::operator=(const Topology&)
{
    throw cRuntimeError(this, "operator= not implemented yet");
}

void Topology::clear()
{
    for (auto& elem : nodes) {
        for (auto& _j : elem->outLinks)
            delete _j; // delete links from their source side
        delete elem;
    }
    nodes.clear();
}

// ---

static bool selectByModulePath(cModule *mod, void *data)
{
    using inet::PatternMatcher;

    // actually, this is selectByModuleFullPathPattern()
    const std::vector<std::string>& v = *(const std::vector<std::string> *)data;
    std::string path = mod->getFullPath();
    for (auto& elem : v)
        if (PatternMatcher(elem.c_str(), true, true, true).matches(path.c_str()))
            return true;

    return false;
}

static bool selectByNedTypeName(cModule *mod, void *data)
{
    const std::vector<std::string>& v = *(const std::vector<std::string> *)data;
    return contains(v, mod->getNedTypeName());
}

static bool selectByProperty(cModule *mod, void *data)
{
    struct ParamData {
        const char *name;
        const char *value;
    };
    ParamData *d = (ParamData *)data;
    cProperty *prop = mod->getProperties()->get(d->name);
    if (!prop)
        return false;
    const char *value = prop->getValue(cProperty::DEFAULTKEY, 0);
    if (d->value)
        return opp_strcmp(value, d->value) == 0;
    else
        return opp_strcmp(value, "false") != 0;
}

static bool selectByParameter(cModule *mod, void *data)
{
    struct PropertyData {
        const char *name;
        const char *value;
    };
    PropertyData *d = (PropertyData *)data;
    return mod->hasPar(d->name) && (d->value == nullptr || mod->par(d->name).str() == std::string(d->value));
}

bool Topology::selectTopologyNode(cModule *mod, void *data)
{
    auto properties = mod->getProperties();
    return properties->get("networkNode") || properties->get("wireJunction");
}

// ---

void Topology::extractByModulePath(const std::vector<std::string>& fullPathPatterns)
{
    extractFromNetwork(selectByModulePath, (void *)&fullPathPatterns);
}

void Topology::extractByNedTypeName(const std::vector<std::string>& nedTypeNames)
{
    extractFromNetwork(selectByNedTypeName, (void *)&nedTypeNames);
}

void Topology::extractByProperty(const char *propertyName, const char *value)
{
    struct {
        const char *name;
        const char *value;
    } data = {
        propertyName, value
    };
    extractFromNetwork(selectByProperty, (void *)&data);
}

void Topology::extractByParameter(const char *paramName, const char *paramValue)
{
    struct {
        const char *name;
        const char *value;
    } data = {
        paramName, paramValue
    };
    extractFromNetwork(selectByParameter, (void *)&data);
}

// ---

static bool selectByPredicate(cModule *mod, void *data)
{
    Topology::Predicate *predicate = (Topology::Predicate *)data;
    return predicate->matches(mod);
}

void Topology::extractFromNetwork(Predicate *predicate)
{
    extractFromNetwork(selectByPredicate, (void *)predicate);
}

void Topology::extractFromNetwork(bool (*predicate)(cModule *, void *), void *data)
{
    clear();

    // Loop through all modules and find those that satisfy the criteria
    int networkId = 0;
    for (int modId = 0; modId <= getSimulation()->getLastComponentId(); modId++) {
        cModule *module = getSimulation()->getModule(modId);
        if (module && predicate(module, data)) {
            Node *node = createNode(module);
            node->setNetworkId(++networkId);
            nodes.push_back(node);
        }
    }

    // Discover out neighbors too.
    for (auto& elem : nodes) {
        // Loop through all its gates and find those which come
        // from or go to modules included in the topology.

        Node *node = elem;
        cModule *mod = getSimulation()->getModule(node->moduleId);

        for (cModule::GateIterator i(mod); !i.end(); i++) {
            cGate *gate = *i;
            if (gate->getType() != cGate::OUTPUT)
                continue;

            // follow path
            cGate *srcGate = gate;
            do {
                gate = gate->getNextGate();
            } while (gate && !predicate(gate->getOwnerModule(), data));

            // if we arrived at a module in the topology, record it.
            if (gate) {
                Link *link = createLink();
                link->srcNode = node;
                link->srcGateId = srcGate->getId();
                link->destNode = getNodeFor(gate->getOwnerModule());
                link->destGateId = gate->getId();
                node->outLinks.push_back(link);
            }
        }
    }

    // fill inLinks vectors
    for (auto& elem : nodes) {
        for (auto& _l : elem->outLinks) {
            Topology::Link *link = _l;
            link->destNode->inLinks.push_back(link);
        }
    }

    for (auto& elem : nodes)
        findNetworks(elem);
}

int Topology::addNode(Node *node)
{
    if (node->moduleId == -1) {
        // elements without module ID are stored at the end
        nodes.push_back(node);
        return nodes.size() - 1;
    }
    else {
        // must find an insertion point because nodes[] is ordered by module ID
        auto it = std::lower_bound(nodes.begin(), nodes.end(), node, lessByModuleId);
        it = nodes.insert(it, node);
        return it - nodes.begin();
    }
}

void Topology::deleteNode(Node *node)
{
    // remove outgoing links
    for (auto& elem : node->outLinks) {
        Link *link = elem;
        unlinkFromDestNode(link);
        delete link;
    }
    node->outLinks.clear();

    // remove incoming links
    for (auto& elem : node->inLinks) {
        Link *link = elem;
        unlinkFromSourceNode(link);
        delete link;
    }
    node->inLinks.clear();

    // remove from nodes[]
    auto it = find(nodes, node);
    ASSERT(it != nodes.end());
    nodes.erase(it);

    delete node;
}

void Topology::addLink(Link *link, Node *srcNode, Node *destNode)
{
    // remove from graph if it's already in
    if (link->srcNode)
        unlinkFromSourceNode(link);
    if (link->destNode)
        unlinkFromDestNode(link);

    // insert
    if (link->srcNode != srcNode)
        link->srcGateId = -1;
    if (link->destNode != destNode)
        link->destGateId = -1;
    link->srcNode = srcNode;
    link->destNode = destNode;
    srcNode->outLinks.push_back(link);
    destNode->inLinks.push_back(link);
}

void Topology::addLink(Link *link, cGate *srcGate, cGate *destGate)
{
    // remove from graph if it's already in
    if (link->srcNode)
        unlinkFromSourceNode(link);
    if (link->destNode)
        unlinkFromDestNode(link);

    // insert
    Node *srcNode = getNodeFor(srcGate->getOwnerModule());
    Node *destNode = getNodeFor(destGate->getOwnerModule());
    if (!srcNode)
        throw cRuntimeError("cTopology::addLink: module of source gate \"%s\" is not in the graph", srcGate->getFullPath().c_str());
    if (!destNode)
        throw cRuntimeError("cTopology::addLink: module of destination gate \"%s\" is not in the graph", destGate->getFullPath().c_str());
    link->srcNode = srcNode;
    link->destNode = destNode;
    link->srcGateId = srcGate->getId();
    link->destGateId = destGate->getId();
    srcNode->outLinks.push_back(link);
    destNode->inLinks.push_back(link);
}

void Topology::deleteLink(Link *link)
{
    unlinkFromSourceNode(link);
    unlinkFromDestNode(link);
    delete link;
}

void Topology::unlinkFromSourceNode(Link *link)
{
    std::vector<Link *>& srcOutLinks = link->srcNode->outLinks;
    auto it = find(srcOutLinks, link);
    ASSERT(it != srcOutLinks.end());
    srcOutLinks.erase(it);
}

void Topology::unlinkFromDestNode(Link *link)
{
    std::vector<Link *>& destInLinks = link->destNode->inLinks;
    auto it = find(destInLinks, link);
    ASSERT(it != destInLinks.end());
    destInLinks.erase(it);
}

Topology::Node *Topology::getNode(int i) const
{
    if (i < 0 || i >= (int)nodes.size())
        throw cRuntimeError(this, "invalid node index %d", i);
    return nodes[i];
}

Topology::Node *Topology::getNodeFor(cModule *mod) const
{
    // binary search because nodes[] is ordered by module ID
    Node tmpNode(mod->getId());
    auto it = std::lower_bound(nodes.begin(), nodes.end(), &tmpNode, lessByModuleId);
    // TODO this does not compile with VC9 (VC10 is OK): auto it = std::lower_bound(nodes.begin(), nodes.end(), mod->getId(), isModuleIdLess);
    return it == nodes.end() || (*it)->moduleId != mod->getId() ? nullptr : *it;
}

void Topology::calculateUnweightedSingleShortestPathsTo(Node *_target) const
{
    // multiple paths not supported :-(

    if (!_target)
        throw cRuntimeError(this, "..ShortestPathTo(): target node is nullptr");
    auto target = _target;

    for (auto& elem : nodes) {
        elem->dist = INFINITY;
        elem->outPaths.clear();
    }
    target->dist = 0;

    std::deque<Node *> q;

    q.push_back(target);

    while (!q.empty()) {
        Node *v = q.front();
        q.pop_front();

        // for each w adjacent to v...
        for (size_t i = 0; i < v->inLinks.size(); i++) {
            if (!v->inLinks[i]->enabled)
                continue;

            Node *w = v->inLinks[i]->srcNode;
            if (!w->enabled)
                continue;

            if (w->dist == INFINITY) {
                w->dist = v->dist + 1;
                q.push_back(w);
            }
            // the first one will be the shortest
            if (!contains(w->outPaths, v->inLinks[i]))
                w->outPaths.push_back(v->inLinks[i]);
        }
    }
}

void Topology::calculateWeightedSingleShortestPathsFrom(Node *source) const
{
    calculateWeightedSingleShortestPaths(source, false);
}

void Topology::calculateWeightedSingleShortestPathsTo(Node *target) const
{
    calculateWeightedSingleShortestPaths(target, true);
}

void Topology::calculateWeightedSingleShortestPaths(Node *initial, bool to) const
{
    if (!initial)
        throw cRuntimeError(this, "calculateWeightedSingleShortestPaths(): initial node is nullptr");

    for (auto& elem : nodes) {
        elem->dist = INFINITY;
        elem->outPaths.clear();
    }
    initial->dist = 0;

    std::list<Node *> q;
    q.push_back(initial);
    while (!q.empty()) {
        Node *current = q.front();
        q.pop_front();
        ASSERT(current->getWeight() >= 0.0);

        // for each w adjacent to v...
        for (int i = 0; i < (to ? current->getNumInLinks() : current->getNumOutLinks()); i++) {
            if (!(to ? current->getLinkIn(i)->isEnabled() : current->getLinkOut(i)->isEnabled()))
                continue;

            Node *remote = to ? current->getLinkIn(i)->getLinkInRemoteNode() : current->getLinkOut(i)->getLinkOutRemoteNode();
            if (!remote->isEnabled())
                continue;

            double linkWeight = to ? current->getLinkIn(i)->getWeight() : current->getLinkOut(i)->getWeight();

            // links with linkWeight == 0 might induce circles
            ASSERT(linkWeight > 0.0);

            double newdist = current->dist + linkWeight;
            if (current != initial)
                newdist += current->getWeight(); // current is not the target, uses weight of current node as price of routing (infinity means current node doesn't route between interfaces)
            if (newdist != INFINITY && remote->dist > newdist) { // it's a valid shorter path from remote to target node
                if (remote->dist != INFINITY)
                    q.remove(remote); // remote is in the queue
                remote->dist = newdist;
                // the first one will be the shortest
                remote->outPaths.erase(std::remove(remote->outPaths.begin(), remote->outPaths.end(), to ? current->inLinks[i] : current->outLinks[i]), remote->outPaths.end());
                remote->outPaths.insert(remote->outPaths.begin(), to ? current->inLinks[i] : current->outLinks[i]);

                // insert remote node to ordered list
                auto it = q.begin();
                for (; it != q.end(); ++it)
                    if ((*it)->dist > newdist)
                        break;

                q.insert(it, remote);
            }
            else if (!contains(remote->outPaths, to ? current->inLinks[i] : current->outLinks[i]))
                (to ? remote : current)->outPaths.push_back(to ? current->inLinks[i] : current->outLinks[i]);
        }
    }
}

void Topology::findNetworks(Node *node)
{
    if (node->isVisited())
        return;

    cModule *mod = getSimulation()->getModule(node->moduleId);
    if (!mod)
        return;

    for (cModule::GateIterator i(mod); !i.end(); i++) {
        cGate *gate = *i;
        if (gate->getType() != cGate::OUTPUT)
            continue;

        // follow path
        do {
            gate = gate->getNextGate();
        } while (gate && !gate->getOwnerModule());

        // if we arrived at a module in the topology, record it.
        if (gate) {
            node->setVisited(true);
            Node *nextNode = getNodeFor(gate->getOwnerModule());
            if (nextNode) {
                if (!nextNode->isVisited()) {
                    nextNode->setNetworkId(node->getNetworkId());
                    findNetworks(nextNode);
                }
            }
        }
    }
}

} // namespace inet

