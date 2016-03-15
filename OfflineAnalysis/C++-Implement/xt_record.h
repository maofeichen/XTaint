/*
 * file: xt_record.h
 * desc: define the data structure to store the data of xtaint log
 */

#ifndef XT_RECORD_H
#define XT_RECORD_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

struct Node_t {
    std::string flag;
    std::string name;
    std::string val;
};

struct Record_t {
    // if true, it's a marker record, only src is used
    bool is_mark;
    struct Node_t src;
    struct Node_t dst;
};

struct Node_Propagate_t {
    int id;
    int p_id;
    int layer;
    int idx;
    std::string insn_addr;
    bool is_src;
    struct Node_t nd;

    /* friend bool operator<(Node_Propagate_t a, */
    /*                       Node_Propagate_t b)  */
    /* { */
    /*     return a.id > b.id; */
    /* } */
};

void read_xtlog(std::ifstream&, std::vector<Record_t>&);
#endif
