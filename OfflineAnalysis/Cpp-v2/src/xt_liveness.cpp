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
    vector<string> alive_buffer;
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
                        XT_Liveness::analyze_function_alive_buffer(v_function_call);

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

    return v_new;
}