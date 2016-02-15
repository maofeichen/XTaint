/*
 * xt_propagate.cpp
 *
 * given a xtaint log file and a source, print out all destinations 
 * that the source can propagate to, level by level
 */

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
vector<Node_Propagate_t> bfs(vector<Record_t>&, queue<Node_Propagate_t>&);
inline string get_insn_addr(int idx, vector<Record_t>&);
bool valid_propagate(struct Node_Propagate_t&, struct Record_t&, vector<Record_t>&, int&);
bool push_to_res(bool&, int&);

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
    struct Node_Propagate_t hit;
    vector<Node_Propagate_t> res;
    queue<Node_Propagate_t> q_propa;
    
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
                q_propa.push(hit);
                break;
            }
        }
        idx++;
    }

    res = bfs(rs, q_propa);
    
    cout << "total results: " << res.size() << endl;
    cout << "----------------------------------------" << endl;
    
    for(vector<Node_Propagate_t>::iterator i = res.begin(); i != res.end(); ++i){
        if(lay != i->layer){
            cout << "----------------------------------------" << endl;
            lay = i->layer;
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
                             queue<Node_Propagate_t>& q_propa)
{
    vector<Node_Propagate_t> res;
    struct Node_Propagate_t curr_nd, next_nd;
    struct Record_t r;
    bool is_valid_propa = false;
    bool within_insn = true;
    bool is_push_res = false;
    int num_propa = 0;
    int j = 0;
    
    while(!q_propa.empty() ){
        num_propa = 0;
        within_insn = true;
        
        curr_nd = q_propa.front();
        res.push_back(curr_nd);

        // if a src node, push its direct dst node into queue
        // except both <name val> are same, ignore 
        if(curr_nd.is_src){
            j = curr_nd.idx;
            if(rs[j].src.name != rs[j].dst.name || \
               rs[j].src.val != rs[j].dst.val){
                next_nd.p_id = curr_nd.id;
                next_nd.id = curr_nd.id + 1;
                next_nd.layer = curr_nd.layer + 1;
                next_nd.idx = j;
                next_nd.is_src = false;

                next_nd.nd.flag = rs[j].dst.flag;
                next_nd.nd.name = rs[j].dst.name;
                next_nd.nd.val = rs[j].dst.val;
                
                q_propa.push(next_nd);
                num_propa++;
            }
        }
        else{ // if a dst node, search all rest srcs in XTaint records
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
                    is_valid_propa = valid_propagate(curr_nd, r, rs, num_propa);

                    if(is_valid_propa){
                        is_push_res = push_to_res(within_insn, num_propa);
                        
                        if(is_push_res) {
                            next_nd.p_id = curr_nd.id;
                            next_nd.id = i * 2;
                            next_nd.layer = curr_nd.layer + 1;
                            next_nd.idx = i;
                            next_nd.is_src = true;

                            next_nd.nd.flag = r.src.flag;
                            next_nd.nd.name = r.src.name;
                            next_nd.nd.val = r.src.val;
                            q_propa.push(next_nd);
                        }
                    }
                }
            }
        }
        q_propa.pop();
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
inline bool valid_propagate(struct Node_Propagate_t& c,
                     struct Record_t& r,
                     vector<Record_t>& rs,
                     int& num_propa)
{
    int len_cur_val = c.nd.val.length();
    int len_r_src_val = r.src.val.length();
    bool is_valid_propa = false;
    
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

    if(is_valid_propa)
        num_propa++;
    
    return is_valid_propa;
}

// determines if it needs to push the final result given flag of within same
// insn, and number of valid propagations hits
bool push_to_res(bool& within_insn, int& num_propa){
    bool is_push_res = false;

    // if with in same insn, can have multiple valid propagations,
    // always push
    if(within_insn)
        is_push_res = true;
    // if not within same insn, can ONLY has one valid propagation
    // outside the guest insn
    else
        if(num_propa == 1)
            is_push_res = true;
    
    return is_push_res;
}
