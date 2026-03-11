#ifndef FUNCTION_META_H
#define FUNCTION_META_H

#include <string>

struct FunctionMeta {
    std::string name;
    std::string source_file;
    std::string source_dir;
    unsigned line_start = 0;
    unsigned bb_count = 0;
    unsigned instructions_count = 0;
};

#endif // FUNCTION_META_H