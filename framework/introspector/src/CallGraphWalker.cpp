// recursive call tree extraction
#include "CallGraphWalker.h"
#include "FunctionInfo.h"
#include "llvm/Analysis/CallGraph.h"

void CallGraphWalker::walkNode(
    CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited
)
{
    for (unsigned i = 0; i < node->size(); i++) {
        CallGraphNode *callee = (*node)[i];
        if (Function *f = callee->getFunction()) {
            FunctionInfo finfo(*f);
            llvm::outs() << std::string(depth * 2, ' ');
            finfo.dump();
            if (visited.insert(f).second) {
                walkNode(callee, depth + 1, visited);
                visited.erase(f);
            }
        }
    }
}

void CallGraphWalker::walk(const std::string &entry_name)
{
    Function *entry_func = m_module.getFunction(entry_name);
    if (!entry_func) {
        llvm::errs() << "error: function '" << entry_name << "' not found\n";
        return;
    }

    CallGraph call_graph(m_module);
    CallGraphNode *entry_node = call_graph[entry_func];

    SmallPtrSet<Function *, 32> visited;
    visited.insert(entry_func);
    walkNode(entry_node, 0, visited);
}