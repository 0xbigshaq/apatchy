// entry point: parse args, load bitcode, run analysis
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include "CallGraphWalker.h"
#include "JsonOutput.h"
#include "WalkResult.h"

using namespace llvm;

int main(int argc, char **argv)
{
    if (argc < 3) {
        llvm::outs() << "usage: test_load <file.bc> <function name>\n";
        return 1;
    }

    LLVMContext Ctx;
    SMDiagnostic Err;
    auto M = parseIRFile(argv[1], Err, Ctx);
    if (!M) {
        Err.print(argv[0], llvm::errs());
        return 1;
    }

    CallGraphWalker walker(*M);
    JsonOutput json_output;
    WalkResult w_result = walker.walk(std::string(argv[2]));
    llvm::json::Object tree = json_output.nodeToJson(w_result.root);
    llvm::outs() << llvm::json::Value(std::move(tree)) << "\n";

    // Walker.walk();
    // Walker.print();

    // FunctionInfo Info(M);
    // Info.extract();
    // Info.print();

    // Output Output(M);
    // Output.print();

    return 0;
}
