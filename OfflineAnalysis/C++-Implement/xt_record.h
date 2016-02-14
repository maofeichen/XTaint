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
    bool isMarker;
    struct Node_t src;
    struct Node_t dst;
};

struct Node_Propagate_t {
    int idx;
    int parent_idx;
    int layer;
    int pos;
    bool isSrc;
    struct Node_t node;
};

void read_xtlog(std::ifstream&, std::vector<Record_t>&);
#endif
