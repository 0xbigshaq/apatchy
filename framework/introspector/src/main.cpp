// entry point: parse args, load bitcode, run analysis
#include <fstream>
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
        llvm::errs() << "usage: wuxi <file.bc> <function> [-f output.json]\n";
        return 1;
    }

    std::string bc_path;
    std::string entry_name;
    std::string out_file;

    // parse positional args and -f flag
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-f" && i + 1 < argc) {
            out_file = argv[++i];
        } else if (pos == 0) {
            bc_path = arg;
            pos++;
        } else if (pos == 1) {
            entry_name = arg;
            pos++;
        }
    }

    if (bc_path.empty() || entry_name.empty()) {
        llvm::errs() << "usage: wuxi <file.bc> <function> [-f output.json]\n";
        return 1;
    }

    LLVMContext Ctx;
    SMDiagnostic Err;
    auto M = parseIRFile(bc_path, Err, Ctx);
    if (!M) {
        Err.print(argv[0], llvm::errs());
        return 1;
    }

    CallGraphWalker walker(*M);
    WalkResult w_result = walker.walk(entry_name);

    JsonOutput json_output;
    llvm::json::Object output = json_output.resultToJson(w_result, entry_name);
    std::string json_str;
    llvm::raw_string_ostream json_stream(json_str);
    json_stream << llvm::json::Value(std::move(output));

    if (!out_file.empty()) {
        std::ofstream ofs(out_file);
        if (!ofs) {
            llvm::errs() << "error: cannot open output file: " << out_file << "\n";
            return 1;
        }
        ofs << json_str << "\n";
    } else {
        llvm::outs() << json_str << "\n";
    }

    return 0;
}
