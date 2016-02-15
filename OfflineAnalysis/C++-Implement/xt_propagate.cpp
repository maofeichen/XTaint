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

const char* XTLOG_PATH = \
    "test-aes-128-single-block-with-size-mark-refine.txt";

void open_xtlog(vector<Record_t>&);
void propagate(struct Node_t, vector<Record_t>&);
vector<Node_Propagate_t> bfs(vector<Record_t>&, queue<Node_Propagate_t>&);

int main()
{
    vector<Record_t> records;
    struct Node_t s;

    open_xtlog(records);
    // cout << "total records: " << records.size() << endl;
    // for(vector<Record_t>::iterator i = records.begin(); i != records.end(); ++i){
    //     cout << "isMarker: " << i->isMarker << endl;
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
    propagate(s, records);
    
    return 0;
}

void open_xtlog(vector<Record_t>& records)
{
    ifstream xtlog(XTLOG_PATH);
    if(xtlog.is_open() ) {
        read_xtlog(xtlog, records);
    }
    xtlog.close();
}

// Given a XTaint log (records) and an source record, display all other records
// that the source record can propagate to. Essentially, a BFS.
//
// A XTaint log contains records and markers.
// 1) a record contains a source node and destiantion node, each node is a
//    triple <flag name val>. A record represents a propagate:
//    src <flag name val> -> dst <flag name val>
void propagate(struct Node_t src, vector<Record_t>& records)
{
    int idx, lay, pos;
    pos = 0;
    lay = 0;
    struct Node_Propagate_t n;
    vector<Node_Propagate_t> res;
    queue<Node_Propagate_t> propa;
    
    // searches the src node in the whole records (first hit)
    for(vector<Record_t>::iterator i = records.begin(); i != records.end(); ++i) {
        if(!i->isMarker){
            n.layer = 0;
            n.parent_idx = 0;
            n.pos = pos;
            // if src hits 
            if(src.name == i->src.name && src.val == i->src.val){
                n.idx = pos * 2;
                n.isSrc = true;
                n.node.flag = i->src.flag;
                n.node.name = i->src.name;
                n.node.val = i->src.val;
                propa.push(n);
                break;
            } else if(src.name == i->dst.name && src.val == i->dst.val){
                n.idx = pos * 2 + 1;
                n.isSrc = false;
                n.node.flag = i->dst.flag;
                n.node.name = i->dst.name;
                n.node.val = i->dst.val;
                propa.push(n);
                break;
            } 
        }
        pos++;
    }

    res = bfs(records, propa);
    
    cout << "total results: " << res.size() << endl;
    cout << "----------------------------------------" << endl;
    
    for(vector<Node_Propagate_t>::iterator i = res.begin(); i != res.end(); ++i){
        if(lay != i->layer){
            cout << "----------------------------------------" << endl;
            lay = i->layer;
        }
        cout << "layer: " << i->layer;
        cout << "\tidx: " << i->idx;
        cout << "\tparent_idx: " << i->parent_idx;
        if(i->isSrc)
            cout << "\tsrc" << endl;
        else
            cout << "\tdst" << endl;

        cout << "flag: " << i->node.flag;
        cout << "\tname: " << i->node.name;
        cout << "\tval: " << i->node.val << "\n"<< endl;
    }
}

vector<Node_Propagate_t> bfs(vector<Record_t>& records,
                             queue<Node_Propagate_t>& propa)
{
    vector<Node_Propagate_t> res;
    struct Node_Propagate_t cur, next;
    struct Record_t r;
    bool is_propa = false;
    bool is_within_insn;
    int propa_num = 0;
    
    while(!propa.empty() ){
        cur = propa.front();
        res.push_back(cur);

        // a src node, push its direct dst node into queue
        // except the name & val of the src and dst are same 
        if(cur.isSrc){
            if(records[cur.pos].src.name != records[cur.pos].dst.name || \
               records[cur.pos].src.val != records[cur.pos].dst.val){
                next.parent_idx = cur.idx;
                next.idx = cur.idx + 1;
                next.layer = cur.layer + 1;
                next.pos = cur.pos;
                next.isSrc = false;

                next.node.flag = records[cur.pos].dst.flag;
                next.node.name = records[cur.pos].dst.name;
                next.node.val = records[cur.pos].dst.val;
                propa.push(next);
            }
        } else{ // a dst node, search all in the records
            is_within_insn = true;
            propa_num = 0;
            for(vector<Record_t>::size_type i = cur.pos + 1; i != records.size(); i++){
                r = records[i];

                // a guest insn marker
                if(r.isMarker && r.src.flag == XT_INSN_ADDR)
                    is_within_insn = false;
                
                if(!r.isMarker){
                    is_propa = false;
                    
                    // conditions considered as valid propagate
                    if(cur.node.name == r.src.name){
                        int cur_val_len = cur.node.val.length();
                        int r_src_val_len = r.src.val.length();
                        if(cur.node.val == r.src.val){
                            is_propa = true;
                            propa_num++;
                        }
                        else if(cur_val_len > r_src_val_len && \
                                cur.node.val.find(r.src.val) != string::npos){
                            is_propa = true;
                            propa_num++;
                        }
                        else if(cur_val_len < r_src_val_len && \
                                r.src.val.find(cur.node.val) != string::npos){
                            is_propa = true;
                            propa_num++;
                        }
                    }

                    if(is_propa){
                        // propagate mul times within same guest insn
                        // but only once cross guest insn
                        if(is_within_insn || \
                           (!is_within_insn && propa_num == 1) ){
                            next.parent_idx = cur.idx;
                            next.idx = i * 2;
                            next.layer = cur.layer + 1;
                            next.pos = i;
                            next.isSrc = true;

                            next.node.flag = r.src.flag;
                            next.node.name = r.src.name;
                            next.node.val = r.src.val;
                            propa.push(next);
                        }
                        
                        if(!is_within_insn)
                            break;
                    }
                }
            }
        }
        propa.pop();
    }
    return res;
}
