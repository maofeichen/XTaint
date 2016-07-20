#ifndef XT_DATA_H
#define XT_DATA_H

#include <string>
#include <vector>

// Buffer Record
struct Buf_Rec_t{
    std::string src_flag;
    std::string src_addr;
    std::string src_val;

    std::string dst_flag;
    std::string dst_addr;
    std::string dst_val;

    std::string s_size;
    std::string this_rec;

    unsigned long addr;
    unsigned int size;
};

// Continue Buffer
struct Cont_Buf_t
{
    unsigned long begin_addr;
    unsigned long size;
};

// Continues Buffers per function call
struct Func_Call_Cont_Buf_t
{
    std::string call_mark;
    std::string sec_call_mark;
    std::string ret_mark;
    std::string sec_ret_mark;
    std::vector<Cont_Buf_t> cont_buf;
};
#endif