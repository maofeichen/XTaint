/**
 * xt_search_avalanche.cpp
 * Search avalanche buffers given a XTaint log.
 */

#include <cassert>
#include <iostream>
#include <stack>
#include <string>
#include <vector>
#include "xt_file.h"
#include "xt_flag.h"
#include "xt_utils.h"

using namespace std;

// char* XTLOG_PATH = \
//     "./Test-File/test-aes-128-oneblock-sizemark-funcmark.txt";
char* XTLOG_PATH = \
    "./Test-File/test-aes-128-oneblock.txt";

vector<string> preprocess(vector<string> &);                // pre-process xtaint log
vector<string> clean_size_mark(vector<string> &);      // clean empty size mark
vector<string> analyze_func_mark(vector<string> &); //  DEPRECATED!
vector<string> clean_empty_func_mark(vector<string> &);
vector<string> clean_func_mark(vector<string> &);
inline bool is_invalid_record(string &);

int main(void)
{
    vector<string> xt_log;

    // xt_log = read_file(XTLOG_PATH);
    // xt_log = preprocess(xt_log);

    XTFile xt_file(XTLOG_PATH);
    xt_log = xt_file.Read();

    // pre-process
    xt_log = preprocess(xt_log);
}

// pre-process xtaint log:
// clean empty size mark
// clean empty function call mark
vector<string> preprocess(vector<string> &v)
{
    vector<string> v_new;
    v_new = clean_size_mark(v);
    v_new = clean_func_mark(v_new);
    return v_new;
}

// v - contain xtaint record line by line
// if a pair of size mark, there is no records between, delete it. For example,
//      20  8   0   
//      24  8   0   
//      20  10  0   
//      24  10  0
// deletes all above
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
            // if a begin mark
            if(b.substr(0,2).compare(XT_SIZE_BEGIN) == 0)
                // if match size
                if(b.substr(3, string::npos).compare(e.substr(3,string::npos) ) == 0 ){
                    v_new.pop_back();
                    continue;
                }
        }
        v_new.push_back(*i);
    }
    // std::cout << "after clean size mark: " << std::endl;
    // for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
    //     std::cout << *i << std::endl; 
    return v_new;
}

// !DEPRECATED
// no need to add level info
//
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
// for example,
//      14   c0795f08    c015baa5    
//      4b  c01ace50    0   
//      18  c0795f04    c015baa5    
//      4c  c01ace80    0  
// first two lines indicate a CALL instruction:
// - 14 is CALL mark
// - come with esp value, top of stack value,
// - 4b is 2nd mark of CALL
// - comes with callee addr
//
// last two lines indicate RET insn
// - 18 is RET mark
// - comes with esp value, top of stack
// - 4c is 2nd mark of RET
// - comes with function end addr
//
// they are match due to the top of stack values are same, and
// since no valid records between, delete them 
// return - new vector
vector<string> clean_empty_func_mark(vector<string> &v)
{
    vector<string> v_new, cv, rv;
    string c, r, rd;
    bool is_empty, is_invalid, is_del_marks;
    
    // clear pair function call marks that empty between
    int sz, idx;
    for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
        // if a 2nd ret insn mark
        if( (*i).substr(0,2).compare(XT_RET_INSN_2nd) == 0){
            r = v_new.back();
            sz = v_new.size();
            c = v_new.at(sz - 3);
            // if an CALL insn mark
            if(c.substr(0,2).compare(XT_CALL_INSN) == 0 || \
                c.substr(0,2).compare(XT_CALL_INSN_FF2) == 0 ){
                // if matches
                cv = split(c.c_str(), '\t');
                rv = split(r.c_str(), '\t');
                assert(cv.size() == rv.size() );
                sz = cv.size();
                if(cv.at(sz - 2).compare(rv.at(sz - 2) ) == 0){
                    // pop last three
                    for(idx = 0; idx < 3; idx++)
                        v_new.pop_back();
                    continue;
                }
            }
        }
        v_new.push_back(*i);
    }
    return v_new;
}

vector<string> clean_func_mark(vector<string> &v)
{
    vector<string> v_new, cv, rv, tmp;
    stack<string> func_mark;
    string c, r, top, rd;
    int sz;
    bool is_empty, is_invalid, is_del_marks;

    v_new = clean_empty_func_mark(v);

    // clear pair function call marks that contain no valid records between
    int num_item;
    for(std::vector<string>::iterator it = v_new.begin(); it != v_new.end(); ++it){
        // if a 2nd RET insn mark
        if( (*it).substr(0,2).compare(XT_RET_INSN_2nd) == 0){
            is_del_marks = false; // alway assume do not del the pair marks unitl it does
            is_invalid = true; // always assume no valid records between at this time
            num_item = 1;
            r = tmp.back();
            // scan reverse to find most recent CALL mark
            std::vector<string>::reverse_iterator j = tmp.rbegin();
            for(; j != tmp.rend(); ++j){
                c = *j;
                // found a CALL mark
                if(c.substr(0,2).compare(XT_CALL_INSN) == 0 || \
                    c.substr(0,2).compare(XT_CALL_INSN_FF2) == 0){
                    cv = split(c.c_str(), '\t');
                    rv = split(r.c_str(), '\t');
                    assert(cv.size() == rv.size() );
                    sz = cv.size();
                    // is CALL & RET marks matched & no valid records between
                    if(cv.at(sz - 2).compare(rv.at(sz - 2) ) == 0 && is_invalid){
                        // del the pair markds and records between
                        tmp.resize(tmp.size() - num_item);
                        is_del_marks = true;
                    } 

                    break; // break inner for loop if a CALL found
                }
                // else if a valid record, set the valid flag to false
                if(is_invalid_record(c) && is_invalid)
                    is_invalid = false;

                num_item++;
            }
            if(!is_del_marks)
                tmp.push_back(*it); // if not del, push the RET mark as well
        }
        else
            tmp.push_back(*it);  // push non RET mark records
    }

/*
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
*/

    v_new.clear();
    for(vector<string>::iterator it = tmp.begin(); it != tmp.end(); ++it)
        v_new.push_back(*it);
    
    // while(!tmp.empty()){
    //     top = func_mark.top();
    //     func_mark.pop();
    //     v_new.insert(v_new.begin(), top);
    // }

    // clean empty again
    v_new = clean_empty_func_mark(v_new);
 
    cout << "after clean function call mark: " << endl;
    for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
        cout << *i << endl; 
    return v_new;   
}

inline bool is_invalid_record(string &rec)
{
    if(rec.substr(0,2).compare(XT_INSN_ADDR) != 0 && \
        rec.substr(0,2).compare(XT_TCG_DEPOSIT) != 0 && \
        rec.substr(0,2).compare(XT_SIZE_BEGIN) != 0 && \
        rec.substr(0,2).compare(XT_SIZE_END) != 0 && \
        rec.substr(0,2).compare(XT_CALL_INSN_2nd) != 0 && \
        rec.substr(0,2).compare(XT_RET_INSN) != 0)
        return true;
    else
        return false;
}