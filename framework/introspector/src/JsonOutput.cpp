
#include "JsonOutput.h"
#include "CallTreeNode.h"
#include <cstdint>

llvm::json::Object JsonOutput::nodeToJson(const struct CallTreeNode &node)
{
    llvm::json::Object obj;
    obj["name"] = node.name;
    obj["site_file"] = node.site_file;
    obj["site_line"] = static_cast<int64_t>(node.site_line);
    obj["site_loc"] = static_cast<int64_t>(node.site_loc);

    llvm::json::Array children;
    for (const CallTreeNode &child : node.children) {
        children.push_back(llvm::json::Value(nodeToJson(child)));
    }
    obj["children"] = std::move(children);
    return obj;
}