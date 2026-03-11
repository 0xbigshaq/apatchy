// recursive call tree extraction
#include "CallGraphWalker.h"
#include "CallTreeNode.h"
#include "FunctionInfo.h"
#include "JsonOutput.h"
#include "llvm/Analysis/CallGraph.h"
#include <llvm-18/llvm/IR/Metadata.h>

CallTreeNode
CallGraphWalker::walkNode(CallGraphNode *node, unsigned depth, SmallPtrSet<Function *, 32> &visited)
{
    CallTreeNode tree_node;
    if (Function *f = node->getFunction()) {
        tree_node.name = f->getName().str();

        for (auto &CR : *node) {
            CallGraphNode *callee_node = CR.second;
            if (Function *callee = callee_node->getFunction()) {
                if (visited.insert(callee).second) {
                    CallTreeNode child = walkNode(callee_node, depth + 1, visited);

                    // set call site from CR.first
                    if (CR.first) {
                        if (auto *cb = dyn_cast<llvm::CallBase>(*CR.first)) {
                            if (const DebugLoc &loc = cb->getDebugLoc()) {
                                child.site_line = loc.getLine();
                                child.site_loc = loc.getCol();
                                child.site_file = loc->getFilename().str();
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
    CallTreeNode root = walkNode(entry_node, 0, visited);
    // llvm::outs() << "root: " << root.name << ", children: " << root.children.size() << "\n";
    JsonOutput json_output;
    llvm::json::Object tree = json_output.nodeToJson(root);
    llvm::outs() << llvm::json::Value(std::move(tree)) << "\n";
}