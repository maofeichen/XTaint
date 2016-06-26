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
// char* XTLOG_PATH = \
//     "./Test-File/test-aes-128-oneblock.txt";
// char* XTLOG_PATH = \
//     "./Test-File/test-aes-128-1B-all-marks.txt";
char* XTLOG_PATH = \
    "./Test-File/test-aes-128-1B-all-identify-in-out-buffer-fake-data.txt";

vector<string> preprocess(vector<string> &);                    // pre-process xtaint log
vector<string> clean_size_mark(vector<string> &);           // clean empty size mark
vector<string> analyze_func_mark(vector<string> &);       //  DEPRECATED!
vector<string> clean_empty_func_mark(vector<string> &);
vector<string> clean_func_mark(vector<string> &);
inline bool is_invalid_record(string &);

vector<string> get_alive_buffers(vector<string> &);               // Temp DEPRECATED!
inline vector<string> filter_alive_buffers(vector<string> &);   // Temp DEPRECATED!
vector<string> filter_nested_buffer(vector<string> &);           // Temp DEPRECATED!
vector<string> analyze_alive_buffer(vector<string> &);

int main(void)
{
    vector<string> xt_log, alive_buffer;

    // xt_log = read_file(XTLOG_PATH);
    // xt_log = preprocess(xt_log);

    XTFile xt_file(XTLOG_PATH);
    xt_log = xt_file.Read();

    // pre-process
    xt_log = preprocess(xt_log);

    // buffer liveness analysis
    // alive_buffer = get_alive_buffers(xt_log);
    // alive_buffer = filter_nested_buffer(alive_buffer);
    alive_buffer = analyze_alive_buffer(xt_log);

    return 0;
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

    // clean empty again
    // v_new = clean_empty_func_mark(v_new);
 
    // cout << "after clean function call mark: " << endl;
    // for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
    //     cout << *i << endl; 

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

//  For whole xtaint log:
//  1. begins with 1st function call END mark, search backward to find if it
//     has matched function call START mark. 
//  2. If it has, find if there is any valid alive buffers. 
//  3. If it has, store them in order
// Parameters:
//      - v:    xtaint log
// Return
//      the alive buffers in order
vector<string> get_alive_buffers(vector<string> &v)
{
    vector<string> alive_buffer, tmp, vc, vr;
    string c, r;
    int i, j, k, sz;
    bool is_mark_pair, is_empty_func_call;

    for(i = 0; i < v.size(); i++){
        // if a 2nd RET mark
        if(v[i].substr(0,2).compare(XT_RET_INSN_2nd) == 0){
            tmp.clear(); 
            tmp.push_back(v[i]); // sotre the 2nd RET mark
            r = v[i - 1]; // 1st RET mark

            // scan backwards find its matched CALL mark
            for(j = i - 1; j >= 0; j--){
                is_mark_pair = false;
                tmp.push_back(v[j]);

                if(v[j].substr(0,2).compare(XT_CALL_INSN) == 0 || \
                    v[j].substr(0,2).compare(XT_CALL_INSN_FF2) == 0){
                    c = v[j];
                    vc = split(v[j].c_str(), '\t');
                    vr = split(r.c_str(), '\t');
                    assert(vc.size() == vr.size());
                    sz = vc.size();

                    // if CALL & RET mark match
                    if(vc.at(sz - 2).compare(vr.at(sz - 2) ) == 0){
                        alive_buffer.push_back(c);

                        // DEBUG
                        // if(vc.at(sz - 2).compare("804a0cd") == 0)
                        //     cout << "function call: AES_encrypt(...); top of stack: 804a0cd" << endl;

                        is_empty_func_call = true;
                        // scan all records between the pairred marks
                        // 1st scan, to determine if it is empty
                        for(vector<string>::reverse_iterator rit = tmp.rbegin(); \
                              rit != tmp.rend(); ++rit){
                            if((*rit).substr(0,2).compare(TCG_QEMU_LD) == 0 || \
                                (*rit).substr(0,2).compare(TCG_QEMU_ST) == 0){
                                if(is_empty_func_call)
                                    is_empty_func_call = false;
                            }
                        }

                        if(!is_empty_func_call){
                            for(vector<string>::reverse_iterator rit = tmp.rbegin(); \
                                  rit != tmp.rend(); ++rit){
                                // save memory buffers and call or ret marks as well
                                if((*rit).substr(0,2).compare(TCG_QEMU_LD) == 0 || \
                                    (*rit).substr(0,2).compare(TCG_QEMU_ST) == 0 || \
                                    (*rit).substr(0,2).compare(XT_CALL_INSN) == 0 || \
                                    (*rit).substr(0,2).compare(XT_CALL_INSN_FF2) == 0 || \
                                    (*rit).substr(0,2).compare(XT_RET_INSN) == 0){

                                    alive_buffer.push_back(*rit);

                                    // if not the outmost  call & ret mark
                                    // if((*rit).compare(c) != 0 && (*rit).compare(r) != 0)
                                    //     alive_buffer.push_back(*rit);
                                }
                            }
                        }

                        // // test if there is memory buffer
                        // is_empty_func_call = true;
                        // for(vector<string>::iterator it = tmp.begin(); \
                        //         it != tmp.end(); ++it)
                        //     if((*it).substr(0,2).compare(TCG_QEMU_LD)  == 0|| \
                        //         (*it).substr(0,2).compare(TCG_QEMU_ST) == 0)
                        //         is_empty_func_call = false;

                        // if(!is_empty_func_call)
                        //     tmp = filter_alive_buffers(tmp);

                        // for(vector<string>::iterator it = tmp.begin(); \
                        //         it != tmp.end(); ++it)
                        //     alive_buffer.push_back(*it);

                        // if empty pair function call, no need to record
                        if(is_empty_func_call)
                            alive_buffer.pop_back();
                        else
                            alive_buffer.push_back(r);

                        is_mark_pair = true;
                    }
                }
                if(is_mark_pair)
                    break;
            }
        }
    }

    for(vector<string>::iterator it = alive_buffer.begin(); it != alive_buffer.end(); ++it)
        cout << *it << endl;

    return alive_buffer;
}

// Even fetches all alive buffers of a fucntion call, they might not be valid
// of all, such as
//      f1 begin
//          mem1
//          f2 begin
//              mem2
//          f2 end
//      f1 end
// mem1 and mem2 are alive in f1, however, we only consider mem1
// is valid, since mem2 belongs a nested function call f2. 
// Thus, need to filter valid alive buffers
// args:
//      - alive_buffer
//          contains all alive buffer for a particular function call, but not
//          all are valid. In reverse order, i.e., from functin end to start
// return:
//      - alive_buffer after fltering, in order
inline vector<string> filter_alive_buffers(vector<string> &alive_buffer)
{
    vector<string> alive_buffer_filter, vc, vr;
    stack<string> nested_func_call;
    string ret, call;
    int sz;

    // push the outmost function call BEGIN marks
    // alive_buffer_filter.push_back(alive_buffer.end()[-1]);
    // alive_buffer_filter.push_back(alive_buffer.end()[-2]);

    for (vector<string>::reverse_iterator rit = alive_buffer.rbegin();
            rit != alive_buffer.rend(); ++rit) {
        // if a CALL mark, push to stack
        if((*rit).substr(0,2).compare(XT_CALL_INSN) == 0 || \
            (*rit).substr(0,2).compare(XT_CALL_INSN_FF2) == 0)
            nested_func_call.push(*rit);
        // if a RET mark, compare to the CALL mark to see if match
        // (which should). If matches, pop the stack
        else if((*rit).substr(0,2).compare(XT_RET_INSN) == 0){
            ret = *rit;
            call = nested_func_call.top();
            vc = split(call.c_str(), '\t');
            vr = split(ret.c_str(), '\t');
            assert(vc.size() == vr.size());
            sz = vc.size();
            // if CALL & RET mark top of stack values are same (match)
            if(vc.at(sz - 2).compare(vr.at(sz - 2) ) == 0)
                nested_func_call.pop();
        }
        // if a memory buffer
        else if((*rit).substr(0,2).compare(TCG_QEMU_LD) == 0 || \
                    (*rit).substr(0,2).compare(TCG_QEMU_ST) == 0)
            // if not in nested function (1 indicates outmost function call)
            if(nested_func_call.size() <= 1)
                alive_buffer_filter.push_back(*rit);
    }

    // push the outmost function call END marks
    // alive_buffer_filter.push_back(alive_buffer.begin()[1]);
    // alive_buffer_filter.push_back(alive_buffer.begin()[0]);

    return alive_buffer_filter;
}

// Even fetches all alive buffers of a fucntion call, they might not be valid
// of all, such as
//      f1 begin
//          mem1
//          f2 begin
//              mem2
//          f2 end
//      f1 end
// mem1 and mem2 are alive in f1, however, we only consider mem1
// is valid, since mem2 belongs a nested function call f2. 
// Thus, need to filter valid alive buffers
// args:
//      - alive_buffer
//          contains all alive buffer for a particular function call, but not
//          all are valid. 
// return:
//      - alive_buffer after fltering 
vector<string> filter_nested_buffer(vector<string> &alive_buffer)
{
    string call, ret, ret_matched;
    vector<string> alive_buffer_filtered, vc, vr;
    int nested_func_layer = 0, idx = 0, j, sz;
    bool is_pair_nested_func;

    for(vector<string>::iterator it = alive_buffer.begin(); \
            it != alive_buffer.end(); ++it){
        if((*it).substr(0,2).compare(XT_CALL_INSN) == 0 || \
            (*it).substr(0,2).compare(XT_CALL_INSN_FF2) == 0){
            if(nested_func_layer > 0){
                // a nested function call
                // begin from this elem, search forward to found its matched 
                // function end mark
                is_pair_nested_func = false;
                for(j = idx; j < alive_buffer.size(); j++){
                    // if a closest RET is found
                    if(alive_buffer[j].substr(0,2).compare(XT_RET_INSN) == 0){
                        call = alive_buffer[idx];
                        ret = alive_buffer[j];

                        vc = split(call.c_str(), '\t');
                        vr = split(ret.c_str(), '\t');
                        assert(vc.size() == vr.size());
                        sz = vc.size();

                        // if CALL & RET mark top of stack values are same (match)
                        if(vc.at(sz - 2).compare(vr.at(sz - 2) ) == 0){
                            is_pair_nested_func = true;
                            ret_matched = ret;
                            // advance the iterator
                            advance(it, j - idx);
                        }
                    }
                }

            }
            nested_func_layer++;
        }
        else if((*it).substr(0,2).compare(XT_RET_INSN) == 0){
            if(nested_func_layer > 0)   // currently in nested call
                nested_func_layer--;

            // iterate to the end of the paired nested call
            // reset the flag
            if((*it).compare(ret_matched) == 0)
                is_pair_nested_func = false;
        }
        alive_buffer_filtered.push_back(*it);
        idx++;
    }

    // for(vector<string>::iterator it = alive_buffer_filtered.begin(); \
    //         it != alive_buffer_filtered.end(); ++it)
    //     cout << *it << endl;

    return alive_buffer_filtered;
}

// analyzes alive buffers for each function call given a xtlog.
// For those buffers are alive for multiple nested function call,
// they are ONLY considerred alive in the innermost function call.
// args:
//      - xtlog: a vector of strings that contains all xtaint records
// return:
//      - alive_buffer: a vector contaiins all alive buffers of each function
//          call. And function calls are sorted with ended first order.
vector<string> analyze_alive_buffer(vector<string> &xt_log)
{
    int idx, sz_mark;
    bool is_invalid_buf;
    string mark_call_2nd, mark_ret;
    stack<string> calls;
    vectro<string> alive_buffer, vec_mark_call, vec_mark_ret;

    for(vector<string>::iterator it = xt_log.begin(); \
            it != xt_log.end(); ++it){
        // If a function call END mark hit
        if((*it).substr(0,2).compare(XT_RET_INSN_2nd) == 0){
            idx = xt_log.end() - it;
            cout << "Index of ret mark to end is: " << idx << endl;

            // scan backward to the begin
            for(vector<string>::reverse_iterator rit = xt_log.rend() - idx; \
                    rit != xt_log.rbegin(); ++rit){
                cout << "scan backward to the bgin:" << endl;
                // cout << "current record: " << *rit << endl;
                is_invalid_buf = true;

                // 2nd funcation call END mark
                if((*rit).substr(0,2).compare(XT_RET_INSN_2nd) == 0){
                    if(calls.empty())
                        calls.push(*rit);
                    else if(calls.size() == 2){  // indicates outermost call are pushed
                        calls.push(*rit);
                        // A nested call hit, set flag to flase
                        is_invalid_buf = false;
                    }
                }
                // function call END mark
                else if((*rit).substr(0,2).compare(XT_RET_INSN) == 0){
                    // ONLY stores outermost and sec outermost calls
                    if(calls.size() == 1 || calls.size() == 3)
                        calls.push(*rit);
                }
                // 2nd function call START mark
                else if((*rit).substr(0,2).compare(XT_CALL_INSN_2nd) == 0){
                    // If outermost call or and with sec outermost call
                    if(calls.size() == 2 || calls.size() == 4)
                        calls.push(*rit);
                }
                // function call START mark
                else if((*rit).substr(0,2).compare(XT_CALL_INSN) == 0 || \
                            (*rit).substr(0,2).compare(XT_CALL_INSN_FF2) == 0){
                    // outermost call END marks and outermost call 2nd START mark ONLY
                    if(calls.size() == 3){ 
                        mark_call_2nd = calls.pop();
                        mark_ret = calls.pop();
                        // Check if call & ret marks are pair (their top of stack value are same)
                        vec_mark_call = split(*rit.c_str(), '\t');
                        vec_mark_ret = split(mark_ret.c_str(), '\t');
                        assert(vec_mark_call.size() == vec_mark_ret.size());
                        sz_mark = vec_mark_call.size();
                        if(vec_mark_call.at(sz_mark -2).compare(vec_mark_ret.at(sz_mark - 2)) != 0)
                            cout << "outermost call START mark is NOT matched with END mark" << endl;

                        // break the loop any way
                        break;
                    }
                    // outermost and sec outermost call END marks with 
                    // sec outermost 2nd START mark
                    else if(calls.size() == 5){
                        mark_call_2nd = calls.pop();
                        
                    }
                }
            }
        }
    }
    return alive_buffer;
}