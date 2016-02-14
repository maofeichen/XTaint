/*
 * file: xt_record.cpp
 */

#include "xt_flag.h"
#include "xt_record.h"
#include "xt_utils.h"

using namespace std;

void read_xtlog(std::ifstream& xtlog, std::vector<Record_t>& records)
{
    string line;
    struct Record_t r;
    while(getline(xtlog,line) ) {
        // remove last '\t'
        line = line.substr(0, line.size() - 1);
        vector<string> str = split(line.c_str(), '\t');

        // analyze first token (flag), to check if it is a marker
        if(str[0] == XT_INSN_ADDR ||\
           str[0] == XT_TCG_DEPOSIT ||\
           str[0] == XT_SIZE_BEGIN ||\
           str[0] == XT_SIZE_END) {
            r.isMarker = true;
            r.src.flag = str[0];
            r.src.name = str[1];
            r.src.val = str[2];
        } else{
            r.isMarker = false;
            r.src.flag = str[0];
            r.src.name = str[1];
            r.src.val = str[2];
            
            r.dst.flag = str[3];
            r.dst.name = str[4];
            r.dst.val = str[5];
        }
        records.push_back(r);
    }
}
