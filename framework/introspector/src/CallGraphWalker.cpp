// recursive call tree extraction
#include "CallGraphWalker.h"
#include "FunctionInfo.h"
#include "llvm/Analysis/CallGraph.h"

void CallGraphWalker::walkNode(
    CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited
)
{
    for (auto &CR : *node) {
        CallGraphNode *callee = CR.second;
        if (Function *f = callee->getFunction()) {
          
            // CR.first is the CallBase* (the call/invoke instruction)
            unsigned call_line = 0;
            if (CR.first) {
                if (auto *cb = dyn_cast<llvm::CallBase>(*CR.first)) {
                    if (const DebugLoc &loc = cb->getDebugLoc()) {
                        call_line = loc.getLine();
                        // f.set_callsite(line);
                    }
                }
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