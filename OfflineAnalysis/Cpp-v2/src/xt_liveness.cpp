#include <cassert>
#include <stack>
#include "xt_flag.h"
#include "xt_liveness.h"
#include "xt_util.h"

// analyzes alive buffers for each function call given a xtlog.
// For those buffers are alive for multiple nested function call,
// they are ONLY considerred alive in the innermost function call.
// args:
//      - xtlog: a vector of strings that contains all xtaint records
// return:
//      - alive_buffer: a vector contaiins all alive buffers of each function
//          call. And function calls are sorted with ended first order.
vector<string> XT_Liveness::analyze_alive_buffer(vector<string> &v)
{
    int idx, idx_call, idx_ret;
    string ret, call;
    vector<string> alive_buffer, tmp;
    vector<string>::iterator it_call, it_ret;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // If a function call END mark hit
        if(XT_Util::equal_mark(*it, flag::XT_RET_INSN_2nd) ){
            ret = *(it - 1);    // ret is previous of 2nd ret mark
            idx = v.end() - it;
            // cout << "Index of ret mark to end is: " << idx << endl;

            // scan backward to the begin
            vector<string>::reverse_iterator rit = v.rbegin() + idx - 1;
            for(; rit != v.rend(); ++rit){
                // if a CALL mark hits
                if(XT_Util::equal_mark(*rit, flag::XT_CALL_INSN) || 
                    XT_Util::equal_mark(*rit, flag::XT_CALL_INSN_FF2) ){
                // if((*rit).substr(0,2).compare(flag::XT_CALL_INSN) == 0 || 
                //     (*rit).substr(0,2).compare(flag::XT_CALL_INSN_FF2) == 0){
                    call = *rit;
                    // if a matched CALL & RET marks
                    if(XT_Util::is_pair_function_mark(call, ret) ){
                        idx_call = v.rend() - rit;
                        idx_ret = it - v.begin();

                        it_call = v.begin() + idx_call - 1;
                        it_ret = v.begin() + idx_ret + 1;
                        vector<string> v_function_call(it_call, it_ret);
                        tmp = XT_Liveness::analyze_function_alive_buffer(v_function_call);

                        if(tmp.size() > 4){
                            for(vector<string>::iterator tmp_it = tmp.begin(); tmp_it != tmp.end(); ++tmp_it)
                                alive_buffer.push_back(*tmp_it);
                        }
                        break;  // break search backward
                    }
                }
            }
        }
    }
    return alive_buffer;
}

// analyzes alive buffers for a particular function call.
vector<string> XT_Liveness::analyze_function_alive_buffer(vector<string> &v)
{
    vector<string> v_new;
    stack<string> nest_function;
    bool is_in_nest_function = false;
    int idx;
    vector<string>::iterator it_call, it_ret;

    // push outermost CALL marks
    v_new.push_back(v[0]);
    v_new.push_back(v[1]);

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        // If a nested CALL mark hits
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) || 
            XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            // if already in nested function, no need to check
            if(!is_in_nest_function){
                idx = it - v.begin();
                it_call = it;
                // finds its matched RET mark
                for(it_ret = v.begin() + idx; it_ret != v.end() - 2; ++it_ret){
                    // if a RET mark hits
                    if(XT_Util::equal_mark(*it_ret, flag::XT_RET_INSN))
                        if(XT_Util::is_pair_function_mark(*it_call, *it_ret) ){
                            is_in_nest_function = true;
                            nest_function.push(*it_call);
                            break;
                        }
                }
            }
        }
        // if a nested RET mark hit
        else if(XT_Util::equal_mark(*it, flag::XT_RET_INSN)){
            if(!nest_function.empty() && XT_Util::is_pair_function_mark(nest_function.top(), *it) ){
                nest_function.pop();
                is_in_nest_function = false;
            }
        }
        // if a mem buffer mark hits
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) || 
            XT_Util::equal_mark(*it, flag::TCG_QEMU_ST))
            if(!is_in_nest_function)
                v_new.push_back(*it);
    }

    // push outer most RET marks
    v_new.push_back(v[v.size() - 2]);
    v_new.push_back(v[v.size() - 1]);

    return v_new;
}