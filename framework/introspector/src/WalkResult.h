#ifndef WALK_RESULT_H
#define WALK_RESULT_H

#include <string>
#include <vector>
#include <map>

#include "CallEdge.h"
#include "CallTreeNode.h"
#include "FunctionMeta.h"

struct WalkResult {
    CallTreeNode root;
    std::map<std::string, FunctionMeta> functions;
    std::vector<CallEdge> edges;
};

#endif // WALK_RESULT_H