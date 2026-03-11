#ifndef JSON_OUTPUT_H
#define JSON_OUTPUT_H

#include "CallTreeNode.h"
#include <string>
#include <vector>
#include <llvm/Support/JSON.h>

class JsonOutput
{
  public:
    JsonOutput()
    {
    };
    llvm::json::Object nodeToJson(const struct CallTreeNode &node);
};

#endif // JSON_OUTPUT_H