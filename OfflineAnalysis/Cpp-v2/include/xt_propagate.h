#ifndef XT_PROPAGATE_H
#define XT_PROPAGATE_H 

#include "xt_data.h"

#include <unordered_set>
#include <vector>

class Propagate
{
private:
    inline NodePropagate propagate_dst(NodePropagate &s, std::vector<Rec> &r);
    inline NodePropagate propagte_src(std::vector<Rec> &v_rec, int i);
    inline void insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res);
    inline bool is_valid_propagate(NodePropagate &currNode, Rec &currRec, std::vector<Rec> &v_rec);

    std::unordered_set<Node, NodeHash> bfs(NodePropagate &s, std::vector<Rec> &r);
public:
    Propagate();
    ~Propagate();
    
};
#endif