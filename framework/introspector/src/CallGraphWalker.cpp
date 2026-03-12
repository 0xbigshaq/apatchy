// recursive call tree extraction
#include "CallGraphWalker.h"
#include "CallEdge.h"
#include "CallTreeNode.h"
#include "FunctionInfo.h"
#include "FunctionMeta.h"
#include "JsonOutput.h"
#include "WalkResult.h"
#include "llvm/Analysis/CallGraph.h"
#include <llvm-18/llvm/IR/Metadata.h>

CallTreeNode CallGraphWalker::walkNode(
    CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited,
    std::map<std::string, FunctionMeta> &func_map, std::vector<CallEdge> &edges
)
{
    CallTreeNode tree_node;
    if (Function *f = node->getFunction()) {
        tree_node.name = f->getName().str();
        FunctionInfo finfo(*f);
        func_map[tree_node.name] = finfo.dump();

        for (auto &CR : *node) {
            CallGraphNode *callee_node = CR.second;
            if (Function *callee = callee_node->getFunction()) {
                if (visited.insert(callee).second) {
                    CallTreeNode child = walkNode(callee_node, depth + 1, visited, func_map, edges);

                    // set call site from CR.first
                    if (CR.first) {
                        if (auto *cb = dyn_cast<llvm::CallBase>(*CR.first)) {
                            if (const DebugLoc &loc = cb->getDebugLoc()) {
                                child.site_line = loc.getLine();
                                child.site_col = loc.getCol();
                                child.site_file = loc->getFilename().str();

                                CallEdge edge;
                                edge.callee = callee->getName();
                                edge.caller = cb->getCaller()->getName();
                                edge.is_indirect = cb->isIndirectCall();
                                edge.site_file = loc->getFilename().str();
                                edge.site_line = loc.getLine();
                                edge.site_col = loc.getCol();
                                edges.push_back(edge);
                            }
                        }
                    }

                    tree_node.children.push_back(child);
                    visited.erase(callee);
                }
            }
        }
    }
    return tree_node;
}

WalkResult CallGraphWalker::walk(const std::string &entry_name)
{
    WalkResult result;
    Function *entry_func = m_module.getFunction(entry_name);
    if (!entry_func) {
        llvm::errs() << "error: function '" << entry_name << "' not found\n";
        return WalkResult{};
    }

    CallGraph call_graph(m_module);
    CallGraphNode *entry_node = call_graph[entry_func];

    SmallPtrSet<Function *, 32> visited;
    visited.insert(entry_func);
    result.root = walkNode(entry_node, 0, visited, result.functions, result.edges);
    return result;
}