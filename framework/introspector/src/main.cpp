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

    std::string entry_name(argv[2]);
    CallGraphWalker walker(*M);
    WalkResult w_result = walker.walk(entry_name);

    JsonOutput json_output;
    llvm::json::Object output = json_output.resultToJson(w_result, entry_name);
    llvm::outs() << llvm::json::Value(std::move(output)) << "\n";

    return 0;
}
