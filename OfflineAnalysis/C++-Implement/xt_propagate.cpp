/*
 * file: xt_propagate.cpp
 * desc: given a xtaint log file and a source, print out all destinations 
 * that the source can propagate to, level by level
 */

#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include "xt_record.h"

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
void propagate(struct Node_t src, vector<Record_t>& records){
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
        cout << "\tparent_idx: " << i->parent_idx << endl;

        cout << "flag: " << i->node.flag;
        cout << "\tname: " << i->node.name;
        cout << "\tval: " << i->node.val << "\n"<< endl;
    }
}


vector<Node_Propagate_t> bfs(vector<Record_t>& records, queue<Node_Propagate_t>& propa){
    vector<Node_Propagate_t> res;
    struct Node_Propagate_t cur, next;
    struct Record_t r;
    
    while(!propa.empty() ){
        cur = propa.front();
        res.push_back(cur);

        // a src node, push its direct dst node into queue
        if(cur.isSrc){
            next.parent_idx = cur.idx;
            next.idx = cur.idx + 1;
            next.layer = cur.layer;
            next.pos = cur.pos;
            next.isSrc = false;

            next.node.flag = records[cur.pos].dst.flag;
            next.node.name = records[cur.pos].dst.name;
            next.node.val = records[cur.pos].dst.val;
            propa.push(next);
        } else{
            for(vector<Record_t>::size_type i = cur.pos + 1; i != records.size(); i++){
                r = records[i];
                if(!r.isMarker){
                    // name & val are same considers a valid propagate
                    if(cur.node.name == r.src.name && \
                       cur.node.val == r.src.val){
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
                }
            }
        }
        
        propa.pop();
    }

    return res;
}
