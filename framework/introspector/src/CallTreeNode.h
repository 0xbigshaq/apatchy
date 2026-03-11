#ifndef CALL_TREE_NODE_H
#define CALL_TREE_NODE_H

#include <string>
#include <vector>

struct CallTreeNode {
    std::string name;
    std::string site_file;
    unsigned site_line = 0;
    unsigned site_loc = 0;
    std::vector<CallTreeNode> children;
};

#endif // CALL_TREE_NODE_H