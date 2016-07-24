#include "xt_flag.h"
#include "xt_propagate.h"
#include "xt_util.h"

#include <cassert>
#include <queue>
#include <string>
#include <unordered_set>
#include <vector>

using namespace std;

unordered_set<Node, NodeHash> Propagate::bfs(NodePropagate &s, vector<Rec> &r)
{
    queue<NodePropagate> q_propagate;
    unordered_set<Node, NodeHash> res;

    NodePropagate currNode, nextNode;
    struct Rec currRec;
    int numHit;
    bool isValidPropagate, isSameInsn;

    q_propagate.push(s);
    while(!q_propagate.empty() ){
        currNode = q_propagate.front();
        q_propagate.pop();

        // if a source node
        if(currNode.isSrc){
            unsigned int i = currNode.pos;
            // can't be a mark
            assert( r[i].isMark == false);
            nextNode = propagate_dst(currNode, r);
            q_propagate.push(nextNode);

            // if it is store to buffer operation, save to propagate result
            Node node = nextNode.n;
            if(XT_Util::equal_mark(node.flag, flag::TCG_QEMU_ST) )
                insert_propagate_result(node, res);
        } else { // if a dst node
            // find valid propagation from dst -> src for afterwards records
            numHit = 0;
            isSameInsn = true;  // assume belongs to same insn at first
            vector<Rec>::size_type i = currNode.pos + 1;
            for(; i != r.size(); i++) {
                isValidPropagate = false;
                currRec = r[i];

                // if cross insn boundary
                if(isSameInsn)
                    if(currRec.isMark && 
                        XT_Util::equal_mark(currRec.regular.src.flag, flag::XT_INSN_ADDR) )
                        isSameInsn = false;

                if(!currRec.isMark){
                    isValidPropagate = is_valid_propagate(currNode, currRec, r);

                    if(isValidPropagate){
                        nextNode = propagte_src(r, i);
                        // is it a load opreration? If so, then it is a memory buffer

                    } // end isValidPropagate
                }
            } // end of for loop
        }
    } // end of while loop
    return res;
}

inline NodePropagate Propagate::propagate_dst(NodePropagate &s, vector<Rec> &r)
{
    NodePropagate d;
    unsigned int i = s.pos;

    d.isSrc = false;
    d.pos = s.pos;
    d.n.flag = r[i].regular.dst.flag;
    d.n.addr = r[i].regular.dst.addr;
    d.n.val = r[i].regular.dst.val;
    d.n.i_addr = r[i].regular.dst.i_addr;
    d.n.sz = r[i].regular.dst.sz;

    return d;
}

inline NodePropagate Propagate::propagte_src(std::vector<Rec> &v_rec, int i)
{
    NodePropagate s;

    s.isSrc = true;
    s.pos = i;
    s.n.flag = v_rec[i].regular.src.flag;
    s.n.addr = v_rec[i].regular.src.addr;
    s.n.val = v_rec[i].regular.src.val;
    s.n.i_addr = v_rec[i].regular.src.i_addr;
    s.n.sz = v_rec[i].regular.src.sz;

    return s;
}

inline void Propagate::insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res)
{
    unordered_set<Node, NodeHash>::const_iterator got = res.find(n);
    // if not in the propagate result
    if(got == res.end() )
        res.insert(n);
}

// dst -> src propagation rules:
//      1. records belong to same insn, can have multiple hits
//      2. records beyond insn, can only have one hit
// if the dst node is a store operation, then if
//      dst.addr == current record src.addr
//      consider valid
// else otherwise
//      case 1 - dst.addr == current record src.addr
inline bool Propagate::is_valid_propagate(NodePropagate &currNode, 
                                                                    Rec &currRec, 
                                                                    vector<Rec> &v_rec)
{
    bool isValidPropagate, isStore; 

    isValidPropagate = false;
    if(XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
        isStore = true;
    else
        isStore = false;

    // is the dst node a store operation, indicating node is a memory buffer
    if(isStore){
        if(currNode.n.addr == currRec.regular.src.addr)
            isValidPropagate = true;
    }else{
        // case 1
        // dst node.addr == current node src.addr
        if(currNode.n.addr == currRec.regular.src.addr){
            // if vals are also same
            if(currNode.n.val == currRec.regular.src.val)
                isValidPropagate = true;
            else if(currNode.n.val.find(currRec.regular.src.val) != string::npos || 
                        currRec.regular.src.val.find(currNode.n.val) != string::npos)
                isValidPropagate = true;
            // specail case: tcg add
            else if(XT_Util::equal_mark(currRec.regular.src.flag, flag::TCG_ADD) )
                isValidPropagate = true;
            // special case: if current node next node is a tcg xor
            else if(XT_Util::equal_mark(v_rec[currNode.pos + 1].regular.src.flag, flag::TCG_XOR) )
                isValidPropagate = true;
        }
        // case 2
        // load pointer: current node val is same with current record's addr
        else if(currNode.n.val == currRec.regular.src.addr && 
                    XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_LD) )
            isValidPropagate = true;
    }

    return isValidPropagate;
}