// FunctionInfo struct + extraction logic
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/DebugInfoMetadata.h>
// #include <llvm/IR/Function.h>
#include "FunctionMeta.h"

using namespace llvm;
class FunctionInfo
{
  public:
    FunctionInfo(llvm::Function &func) : m_func(func){};
    FunctionMeta dump();

  private:
    llvm::Function &m_func;
};