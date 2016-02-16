/*
 * xt_propagate.cpp
 *
 * given a xtaint log file and a source, print out all destinations 
 * that the source can propagate to, level by level
 */

#include <algorithm>
#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include "xt_record.h"
#include "xt_flag.h"

using namespace std;

// const char* XTLOG_PATH =                                  \
//     "test-aes-128-single-block-with-size-mark-refine.txt";

const char* XTLOG_PATH =                                    \
    "test-aes-single-block-temp_name-as-name-refine.txt";

void open_xtlog(vector<Record_t>&);
void propagate(struct Node_t, vector<Record_t>&);
vector<Node_Propagate_t> bfs(vector<Record_t>&,
                             vector<Node_Propagate_t>&,
                             queue<Node_Propagate_t>&);

inline string get_insn_addr(int idx, vector<Record_t>&);
inline bool is_local_mem_addr(struct Node_Propagate_t&);
bool is_valid_propagate(struct Node_Propagate_t&, struct Record_t&, vector<Record_t>&);
bool is_push_to_res(bool&, int&);

Node_Propagate_t propag_dirt_dst_node(Node_Propagate_t&, vector<Record_t>&);
Node_Propagate_t propag_to_src_node(Node_Propagate_t&,
                                    vector<Record_t>&,
                                    int);

void insert_mem_node(vector<Node_Propagate_t>&, Node_Propagate_t&, int&);
bool compa_mem_node(const Node_Propagate_t&, const Node_Propagate_t&);

int main()
{
    vector<Record_t> rs;
    struct Node_t s;

    open_xtlog(rs);
    // cout << "total record number: " << rs.size() << endl;
    // for(vector<Record_t>::iterator i = rs.begin(); i != rs.end(); ++i){
    //     cout << "is_mark: " << i->is_mark << endl;
    //     cout << "src flag: " << i->src.flag << endl;
    //     cout << "src name: " << i->src.name << endl;
    //     cout << "src val: " << i->src.val << endl;

    //     cout << "dst flag: " << i->dst.flag << endl;
    //     cout << "dst name: " << i->dst.name << endl;
    //     cout << "dst val: " << i->dst.val<< endl;
    // }
    
    s.flag = "34";
    s.name = "bffff747";
    s.val = "a8";
    propagate(s, rs);
    
    return 0;
}

void open_xtlog(vector<Record_t>& rs)
{
    ifstream xtlog(XTLOG_PATH);
    if(xtlog.is_open() ) {
        read_xtlog(xtlog, rs);
    }
    xtlog.close();
}

// Given a XTaint log (records) and an source node, display all other
// nodes that the source node can propagate to. Using a BFS.
//
// A XTaint log contains records and markers.
// 1) a record contains a source node and destiantion node, each node is a
//    triple <flag name val>.
//    A record represents a propagate:
//    src <flag name val> -> dst <flag name val>
//
// Param
//    - src: src node
//    - records: whole XTaint records 
void propagate(struct Node_t src, vector<Record_t>& rs)
{
    int id = 0, lay = 0, idx = 0;
    bool is_src_found = false;
    bool is_local_mem = false;
    string insn_addr = "";
    struct Node_Propagate_t hit;
    vector<Node_Propagate_t> res;
    queue<Node_Propagate_t> q_propa;
    vector<Node_Propagate_t> q_mem_propa;
    
    // searches the src node in XTaint records (first hit)
    for(vector<Record_t>::iterator i = rs.begin(); i != rs.end(); ++i) {
        if(!i->is_mark){
            // if src hits 
            if(src.name == i->src.name && src.val == i->src.val){
                is_src_found = true;
                
                hit.id = idx * 2;
                hit.is_src = true;
                hit.nd.flag = i->src.flag;
                hit.nd.name = i->src.name;
                hit.nd.val = i->src.val;
            } else if(src.name == i->dst.name && src.val == i->dst.val){
                is_src_found = true;               
                
                hit.id = idx * 2 + 1;
                hit.is_src = false;
                hit.nd.flag = i->dst.flag;
                hit.nd.name = i->dst.name;
                hit.nd.val = i->dst.val;
            }

            if(is_src_found){
                hit.layer = 0;
                hit.p_id = 0;
                hit.idx = idx;
                hit.insn_addr = get_insn_addr(idx, rs);

                is_local_mem = is_local_mem_addr(hit);
                if(is_local_mem)
                    q_mem_propa.push_back(hit);
                else
                    q_propa.push(hit);
                break;
            }
        }
        idx++;
    }

    res = bfs(rs, q_mem_propa, q_propa);
    
    cout << "total results: " << res.size() << endl;
    cout << "------------------------------" << endl;
    
    for(vector<Node_Propagate_t>::iterator i = res.begin(); i != res.end(); ++i){
        if(lay != i->layer){
            cout << "------------------------------" << endl;
            lay = i->layer;
        }

        if(insn_addr != i->insn_addr){
            insn_addr = i->insn_addr;
            cout << "==============================" << endl;
            cout << "guest insn addr: " << insn_addr << endl;
            cout << "==============================" << endl;
        }
        
        cout << "layer: " << i->layer;
        cout << "\tid: " << i->id;
        cout << "\tp_id: " << i->p_id;
        if(i->is_src)
            cout << "\tsrc" << endl;
        else
            cout << "\tdst" << endl;

        cout << "flag: " << i->nd.flag;
        cout << "\tname: " << i->nd.name;
        cout << "\tval: " << i->nd.val << "\n"<< endl;
    }
}

vector<Node_Propagate_t> bfs(vector<Record_t>& rs,
                             vector<Node_Propagate_t>& q_mem_propa,
                             queue<Node_Propagate_t>& q_propa)
{
    vector<Node_Propagate_t> res;
    struct Node_Propagate_t curr_nd, next_nd;
    struct Record_t r;
    bool is_valid_propa = false;
    bool within_insn = true;
    bool is_push_res = false;
    bool is_local_mem = false;
    int num_propa = 0;
    int j = 0;

    while(!q_mem_propa.empty() ){

    l_proc_q_propa:
        // first process non mem propagation
        while(!q_propa.empty() ){
            num_propa = 0;
            within_insn = true;
            is_local_mem = false;

            curr_nd = q_propa.front();
            res.push_back(curr_nd);

            // if a src node, propagate its direct
            // dst node in same record
            if(curr_nd.is_src){
                j = curr_nd.idx;
                // if both <name val> are same, ignore
                if(rs[j].src.name != rs[j].dst.name || \
                   rs[j].src.val != rs[j].dst.val){
                    next_nd = propag_dirt_dst_node(curr_nd, rs);

                    // a dst node, even it's in local mem,
                    // NO need store in mem queue
                    q_propa.push(next_nd);
                    num_propa++;
                }
            }
            // if a dst node
            else{
                num_propa = 0;
                for(vector<Record_t>::size_type i = curr_nd.idx + 1; i != rs.size(); i++){
                    is_valid_propa = false;
                    r = rs[i];

                    // if next guest insn marker is found, set flag false
                    if(within_insn){
                        if(r.is_mark && r.src.flag == XT_INSN_ADDR)
                            within_insn = false;
                    }

                    // if regular record
                    if(!r.is_mark){
                        // is current record's src a valid propagation
                        is_valid_propa = is_valid_propagate(curr_nd, r, rs);

                        if(is_valid_propa){
                            // valid, can get its propagated src node
                            next_nd = propag_to_src_node(curr_nd, rs, i);

                            // if a local mem node, always push to mem queue
                            is_local_mem = is_local_mem_addr(next_nd);
                            if(is_local_mem)
                                insert_mem_node(q_mem_propa, next_nd, num_propa);
                                // q_mem_propa.push(next_nd);
                                // num_propa++;
                            else{
                                // even it might be a valid propagation,
                                // but need to determin if push to regular queue
                                is_push_res = is_push_to_res(within_insn, num_propa);
                                if(is_push_res){ 
                                    q_propa.push(next_nd);
                                    num_propa++;
                                }
                            }
                        }
                    }

                    // if 1) not within same guest insn
                    // 2) already have 1 propagate hit
                    // 3) NOT a local mem addr
                    // can break the for loop
                    if(!within_insn && num_propa >= 1)
                        if(!is_local_mem_addr(curr_nd) )
                            break;
                } // end for loop
            }
            q_propa.pop();
        }

        if(!q_mem_propa.empty() ){
            // begin to process mem queue
            curr_nd = q_mem_propa[0];
            res.push_back(curr_nd);

            // mem queue only containt nodes are in src
            if(curr_nd.is_src){
                j = curr_nd.idx;
                // if both <name val> are same, ignore
                if(rs[j].src.name != rs[j].dst.name || \
                   rs[j].src.val != rs[j].dst.val){
                    next_nd = propag_dirt_dst_node(curr_nd, rs);

                    // a dst node, even it's in local mem,
                    // NO need store in mem queue
                    q_propa.push(next_nd);
                    num_propa++;
                }
            }

            // q_mem_propa.pop();
            q_mem_propa.erase(q_mem_propa.begin() );
        }

        if(!q_propa.empty() )
            goto l_proc_q_propa;
    }
    
    return res;
}

// gets a record's insn addr given its position index of whole XTaint records
// param: int pos: position index of XTaint records
// return: its insn addr
inline string get_insn_addr(int idx, vector<Record_t>& rs)
{
    int i = idx;
    while(i >= 0){
        if(rs[i].is_mark && rs[i].src.flag == XT_INSN_ADDR)
            return rs[i].src.name;
        i--;
    }
    return "";
}

// determins if it is a valid propagtion give a current dst node in queue
// and its compare record
// return: ture if valid, else false
inline bool is_valid_propagate(struct Node_Propagate_t& c,
                     struct Record_t& r,
                     vector<Record_t>& rs)
{
    int len_cur_val = c.nd.val.length();
    int len_r_src_val = r.src.val.length();
    bool is_valid_propa = false;
    bool is_local_mem = is_local_mem_addr(c);

    
    if(!is_local_mem){
        // case 1: current dst node name MUST be same with record src name
        if(c.nd.name == r.src.name){
            if(c.nd.val == r.src.val)
                is_valid_propa = true;
            // if current dst node val contatins record src val
            else if(len_cur_val > len_r_src_val && \
                    c.nd.val.find(r.src.val) != string::npos)
                is_valid_propa = true;
            // if record src val contains current dst node val
            else if(len_cur_val < len_r_src_val && \
                    r.src.val.find(c.nd.val) != string::npos)
                is_valid_propa = true;
            // special case: tcg add
            else if(r.src.flag == TCG_ADD)
                is_valid_propa = true;
            // special case: tcg xor
            // if current node's next record is a xor
            else if(rs[c.idx + 1].src.flag == TCG_XOR)
                is_valid_propa = true;
        }
        // case 2: load pointer, value as name
        // val len should large than 7 (addr)
        else if(c.nd.val == r.src.name && \
                c.nd.val.length() >= 7)
            is_valid_propa = true;
    }
    // local mem node only <name val> are same
    // consider as valid
    else{
        if(c.nd.name == r.src.name && c.nd.val == r.src.val)
            is_valid_propa = true;
    }

    return is_valid_propa;
}

// determines if it needs to push the final result given flag of within same
// insn, and number of valid propagations hits
bool is_push_to_res(bool& within_insn, int& num_propa)
{
    bool is_push_res = false;

    // if within same insn, can have multiple valid propagations,
    // always push
    if(within_insn)
        is_push_res = true;
    // if not within same insn, can ONLY has one valid propagation
    // outside the guest insn
    else
        if(num_propa < 1)
            is_push_res = true;
    
    return is_push_res;
}

// determins if a node is a local memory addr
inline bool is_local_mem_addr(struct Node_Propagate_t& n)
{
    // if name starts with 'b' and length large than 7
    // consider a local mem addr
    if(n.nd.name[0] == 'b' &&
       n.nd.name.length() >= 7)
        return true;

    return false;
}

// if a src node in current queue, push its direct dst node into queue
// except both <name val> are same, ignore 
Node_Propagate_t propag_dirt_dst_node(Node_Propagate_t& curr_nd,
                                      vector<Record_t>& rs)
{
    int i = curr_nd.idx;
    struct Node_Propagate_t next_nd;

    // if both <name val> are same, ignore

    next_nd.p_id = curr_nd.id;
    next_nd.id = curr_nd.id + 1;
    next_nd.layer = curr_nd.layer + 1;
    next_nd.idx = i;
    next_nd.is_src = false;
    next_nd.insn_addr = get_insn_addr(i, rs);

    next_nd.nd.flag = rs[i].dst.flag;
    next_nd.nd.name = rs[i].dst.name;
    next_nd.nd.val = rs[i].dst.val;
    
    return next_nd;
}

// propagate from dst node to rest src node in records
Node_Propagate_t propag_to_src_node(Node_Propagate_t& curr_nd,
                                    vector<Record_t>& rs,
                                    int i)
{
    struct Node_Propagate_t next_nd;

    next_nd.p_id = curr_nd.id;
    next_nd.id = i * 2;
    next_nd.layer = curr_nd.layer + 1;
    next_nd.idx = i;
    next_nd.is_src = true;
    next_nd.insn_addr = get_insn_addr(i, rs);

    next_nd.nd.flag = rs[i].src.flag;
    next_nd.nd.name = rs[i].src.name;
    next_nd.nd.val = rs[i].src.val;

    return next_nd;
}


// compare two local memory nodes
// return: true if which id is smaller
bool compa_mem_node(const Node_Propagate_t& a, const Node_Propagate_t& b)
{
    return a.id < b.id; 
}

// insert a local memory node
void insert_mem_node(vector<Node_Propagate_t>& q_mem_propa, Node_Propagate_t& nd, int& num_propa)
{
    bool has_node = false;

    // if alreay has the memory node, no need to insert
    for(vector<Node_Propagate_t>::iterator it = q_mem_propa.begin();
        it != q_mem_propa.end(); ++it){
        if(it->id == nd.id)
            has_node = true;
    }

    if(!has_node){
        q_mem_propa.push_back(nd);
        num_propa++;
        // sort by id
        sort(q_mem_propa.begin(), q_mem_propa.end(), compa_mem_node);
    }
}
