#ifndef JSON_OUTPUT_H
#define JSON_OUTPUT_H

#include "CallEdge.h"
#include "CallTreeNode.h"
#include "FunctionMeta.h"
#include "WalkResult.h"
#include <string>
#include <vector>
#include <map>
#include <llvm/Support/JSON.h>

class JsonOutput
{
  public:
    JsonOutput(){};
    llvm::json::Object nodeToJson(const struct CallTreeNode &node);
    llvm::json::Object edgeToJson(const struct CallEdge &edge);
    llvm::json::Object functionToJson(const struct FunctionMeta &meta);
    llvm::json::Object resultToJson(const struct WalkResult &result, const std::string &entry_name);
};

#endif // JSON_OUTPUT_H
