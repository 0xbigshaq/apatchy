// FunctionInfo struct + extraction logic
#include "FunctionInfo.h"
#include "FunctionMeta.h"

FunctionMeta FunctionInfo::dump()
{
    FunctionMeta result;
    if (llvm::DISubprogram *subroutine = m_func.getSubprogram()) {
        result.name = subroutine->getName().str();
        result.source_file = subroutine->getFilename().str();
        result.source_dir = subroutine->getDirectory().str();
        result.line_start = subroutine->getLine();
        result.bb_count = m_func.size();
        unsigned count = 0;
        for (BasicBlock &bb : m_func) {
            count += bb.size();
        }
        result.instructions_count = count;
    }
    return result;
}