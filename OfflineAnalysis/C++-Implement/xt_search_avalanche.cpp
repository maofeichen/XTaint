/**
 * xt_search_avalanche.cpp
 * Search avalanche buffers given a XTaint log.
 */

#include <iostream>
#include <fstream>
#include <stack>
#include <string>
#include <vector>
#include "xt_file.h"
#include "xt_flag.h"
#include "xt_utils.h"

using namespace std;

char* XTLOG_PATH = \
    "./Test-File/test-aes-128-oneblock-sizemark-funcmark.txt";

vector<string> preprocess(vector<string> &);
vector<string> clean_size_mark(vector<string> &);
vector<string> analyze_func_mark(vector<string> &);
vector<string> clean_func_mark(vector<string> &);

int main(void)
{
    // vector<string> xt_log_str;

    // xt_log_str = read_file(XTLOG_PATH);
    // xt_log_str = preprocess(xt_log_str);

    XTFile xt_file(XTLOG_PATH);
    xt_file.Read();
}


vector<string> preprocess(vector<string> &v)
{
    vector<string> v_new;
    v_new = clean_size_mark(v);
    v_new = analyze_func_mark(v_new);
    v_new = clean_func_mark(v_new);
    return v_new;
}

// v - contain xtaint record line by line
// if a pair of size mark, there is no records between, delete it
// return - new vector
vector<string> clean_size_mark(vector<string> &v)
{
    vector<string> v_new;
    string b, e;
    
    for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
        // if a size end mark
        if( (*i).substr(0,2).compare(XT_SIZE_END) == 0){
            e = *i;
            b = v_new.back();
            // if a match size begin mark
            if(b.substr(0,2).compare(XT_SIZE_BEGIN) == 0)
                if(b.substr(3, string::npos).compare(e.substr(3,string::npos) ) == 0 ){
                    v_new.pop_back();
                    continue;
                }
        }
        v_new.push_back(*i);
    }
    // cout << "after clean size mark: " << endl;
    // for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
    //     cout << *i << endl; 
    return v_new;
}

// v - contain xtaint record line by line
// add level info for each call and ret mark, indicating their
// matched info
// return - new vector
vector<string> analyze_func_mark(vector<string> &v)
{
    int lv = 0;
    vector<string> v_new;
    string c,r;

    for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
        v_new.push_back(*i);
        if((*i).substr(0,2).compare(XT_CALL_INSN) == 0 ){
            c = *i;
            c.append(std::to_string(lv));
            v_new.pop_back();
            v_new.push_back(c);
            lv++;
        }
        else if((*i).substr(0,2).compare(XT_RET_INSN) == 0){
            r = *i;
            lv--;
            r.append(std::to_string(lv));
            v_new.pop_back();
            v_new.push_back(r);
        }
    }
    // cout << "after analyze function call mark: " << endl;
    // for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
    //     cout << *i << endl; 
    return v_new;
}

// v - contain xtaint record line by line
// if a pair of function call mark, there is no records between, delete it
// return - new vector
vector<string> clean_func_mark(vector<string> &v)
{
    vector<string> v_new, cv, rv, tmp;
    stack<string> func_mark;
    string c, r, top, rd;
    int pos;
    bool is_empty;
    
    // clear pair function call marks that empty between
    for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
        // if a ret insn mark
        if( (*i).substr(0,2).compare(XT_RET_INSN) == 0){
            r = *i;
            c = v_new.back();
            // if a match call insn mark
            if(c.substr(0,2).compare(XT_CALL_INSN) == 0){
                cv = split(c.c_str(), '\t');
                rv = split(r.c_str(), '\t');
                if(cv.back().compare(rv.back() ) == 0){
                    v_new.pop_back();
                    continue;
                }
            }
        }
        v_new.push_back(*i);
    }

    // clear pair function call marks that contain no valid records between
    for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i){
        rd = *i;
        // if a RET mark
        if(rd.substr(0,2).compare(XT_RET_INSN) == 0){
            r = *i;
            // always assume pair is invalid at this time
            is_empty = true;
            // scan reverse try to find a matched called
            if(!tmp.empty()){
                int nitem = 1;
                vector<string>::reverse_iterator j = tmp.rbegin();
                for(; j != tmp.rend(); ++j){
                    c = *j;
                    // found a CALL mark
                    if(c.substr(0,2).compare(XT_CALL_INSN) == 0){
                        cv = split(c.c_str(), '\t');
                        rv = split(r.c_str(), '\t');
                        // if CALL & RET mark are matched & invlid
                        if(cv.back().compare(rv.back() ) == 0 && is_empty)
                            tmp.resize(tmp.size() - nitem);
                        break; // found a CALL break
                    }
                    // else if it is a record, do NOT delete the pair, set flag to false
                    else if(c.substr(0,2).compare(XT_INSN_ADDR) != 0 && \
                            c.substr(0,2).compare(XT_TCG_DEPOSIT) != 0 && \
                            c.substr(0,2).compare(XT_SIZE_BEGIN) != 0 && \
                            c.substr(0,2).compare(XT_SIZE_END) != 0 && \
                            is_empty)
                        is_empty = false;
                    nitem++;
                }
            }
            
            if(!is_empty)
                tmp.push_back(rd);
        }else
            tmp.push_back(rd);
    }

    // clear pair function call marks that contain no valid records between
    // for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i){
    //     if((*i).substr(0,2).compare(XT_RET_INSN) == 0){
    //         is_empty = true;
    //         vector<string> tmp;
    //         while(!func_mark.empty()){
    //             top = func_mark.top();
    //             tmp.push_back(top);
    //             func_mark.pop();
    //             if(top.substr(0,2).compare(XT_CALL_INSN) == 0){
    //                 cv = split(top.c_str(), '\t');
    //                 rv = split((*i).c_str(), '\t');
    //                 if(cv.back().compare(rv.back() ) == 0 && is_empty ){
    //                     // do nothing
    //                 }else{
    //                     for(vector<string>::iterator j = tmp.end(); \
    //                         j != tmp.begin(); --j)
    //                         func_mark.push(*j);
    //                     // push the ret insn itself
    //                     func_mark.push(*i);
    //                 }
    //                 break;
    //             }
    //             else if(top.substr(0,2).compare(XT_INSN_ADDR) != 0 &&  \
    //                     top.substr(0,2).compare(XT_TCG_DEPOSIT) != 0 && \
    //                     top.substr(0,2).compare(XT_SIZE_BEGIN) != 0 && \
    //                     top.substr(0,2).compare(XT_SIZE_END) != 0)
    //                 if(is_empty)
    //                     is_empty = false;
    //         }
    //     }else
    //         func_mark.push(*i);
    // }

    v_new.clear();
    for(vector<string>::iterator i = tmp.begin(); i != tmp.end(); ++i)
        v_new.push_back(*i);
    
    // while(!tmp.empty()){
    //     top = func_mark.top();
    //     func_mark.pop();
    //     v_new.insert(v_new.begin(), top);
    // }
        
    cout << "after clean function call mark: " << endl;
    for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
        cout << *i << endl; 
    return v_new;   
}
