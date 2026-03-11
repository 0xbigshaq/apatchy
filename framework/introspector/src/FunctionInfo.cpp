// FunctionInfo struct + extraction logic
#include "FunctionInfo.h"

void FunctionInfo::dump()
{

    if (llvm::DISubprogram *subroutine = m_func.getSubprogram()) {
        // source-level name
        StringRef name = subroutine->getName();

        // mangled name
        // StringRef Linkage = subroutine->getLinkageName();

        // "server/request.c:1337"
        StringRef file = subroutine->getFilename();
        unsigned int line = subroutine->getLine();

        // "/home/.../httpd"
        StringRef dir = subroutine->getDirectory();

        llvm::outs() << "" << name << "()\t";
        //   llvm::outs() << "Linkage: " << Linkage << "\t";
        llvm::outs() << " @ "
                     << ".../" << file;
        llvm::outs() << ":" << line << "\n";
    }
}