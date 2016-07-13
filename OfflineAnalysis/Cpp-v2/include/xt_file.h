#ifndef XT_FILE_H
#define XT_FILE_H

#include <string>
#include <vector>
#include "xt_data.h"

using namespace std;

class XT_File
{
private:
    std::string path_r;
public:
    XT_File(std::string);

    std::vector<std::string> read();
    void write(std::string, std::vector<std::string> &);
    void write_continue_buffer(string, vector<Func_Call_Cont_Buf_t> &);
}; 
#endif