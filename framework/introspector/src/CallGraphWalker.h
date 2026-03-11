// recursive call tree extraction
#ifndef CALL_GRAPH_WALKER_H
#define CALL_GRAPH_WALKER_H

#include "CallTreeNode.h"
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
    void walk(const std::string &entry_name = "main");

  private:
    CallTreeNode
    walkNode(CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited);
    llvm::Module &m_module;
};

#endif // CALL_GRAPH_WALKER_H