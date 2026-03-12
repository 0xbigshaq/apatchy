
#include "JsonOutput.h"
#include "CallTreeNode.h"
#include <cstdint>

llvm::json::Object JsonOutput::nodeToJson(const struct CallTreeNode &node)
{
    llvm::json::Object obj;
    obj["name"] = node.name;
    obj["site_file"] = node.site_file;
    obj["site_line"] = static_cast<int64_t>(node.site_line);
    obj["site_col"] = static_cast<int64_t>(node.site_col);

    llvm::json::Array children;
    for (const CallTreeNode &child : node.children) {
        children.push_back(llvm::json::Value(nodeToJson(child)));
    }
    obj["children"] = std::move(children);
    return obj;
}

llvm::json::Object JsonOutput::edgeToJson(const struct CallEdge &edge)
{
    llvm::json::Object obj;
    obj["caller"] = edge.caller;
    obj["callee"] = edge.callee;
    obj["site_file"] = edge.site_file;
    obj["site_line"] = static_cast<int64_t>(edge.site_line);
    obj["site_col"] = static_cast<int64_t>(edge.site_col);
    obj["is_indirect"] = edge.is_indirect;
    return obj;
}

llvm::json::Object JsonOutput::functionToJson(const struct FunctionMeta &meta)
{
    llvm::json::Object obj;
    obj["source_file"] = meta.source_file;
    obj["source_dir"] = meta.source_dir;
    obj["line_start"] = static_cast<int64_t>(meta.line_start);
    obj["bb_count"] = static_cast<int64_t>(meta.bb_count);
    obj["instruction_count"] = static_cast<int64_t>(meta.instructions_count);
    return obj;
}

llvm::json::Object JsonOutput::resultToJson(const struct WalkResult &result, const std::string &entry_name)
{
    llvm::json::Object root;

    llvm::json::Object metadata;
    metadata["entry_point"] = entry_name;
    root["metadata"] = std::move(metadata);

    llvm::json::Object functions;
    for (auto &[name, meta] : result.functions) {
        functions[name] = llvm::json::Value(functionToJson(meta));
    }
    root["functions"] = std::move(functions);

    root["call_tree"] = llvm::json::Value(nodeToJson(result.root));

    llvm::json::Array edges;
    for (const CallEdge &edge : result.edges) {
        edges.push_back(llvm::json::Value(edgeToJson(edge)));
    }
    root["call_edges"] = std::move(edges);

    return root;
}
