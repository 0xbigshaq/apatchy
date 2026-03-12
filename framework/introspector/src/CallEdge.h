#ifndef CALL_EDGE_H
#define CALL_EDGE_H

#include <string>
#include <vector>

struct CallEdge {
    std::string caller;
    std::string callee;
    std::string site_file;
    unsigned site_line = 0;
    unsigned site_col = 0;
    bool is_indirect = false;
};

#endif // CALL_EDGE_H