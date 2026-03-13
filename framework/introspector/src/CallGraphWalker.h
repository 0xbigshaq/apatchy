// recursive call tree extraction
#ifndef CALL_GRAPH_WALKER_H
#define CALL_GRAPH_WALKER_H

#include "CallEdge.h"
#include "CallTreeNode.h"
#include "FunctionMeta.h"
#include "WalkResult.h"
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Module.h>
using namespace llvm;

class CallGraphWalker
{
  public:
    CallGraphWalker(llvm::Module &module) : m_module(module)
    {
    }
    WalkResult walk(const std::string &entry_name = "main");

  private:
    CallTreeNode walkNode(
        CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited,
        std::map<std::string, FunctionMeta> &func_map, std::vector<CallEdge> &edges
    );
    CallTreeNode shallowNode(
        CallGraphNode *node, unsigned max_depth,
        std::map<std::string, FunctionMeta> &func_map
    );
    llvm::Module &m_module;
};

#endif // CALL_GRAPH_WALKER_H