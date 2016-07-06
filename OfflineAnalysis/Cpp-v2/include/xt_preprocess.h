#ifndef XT_PREPROCESS_H
#define XT_PREPROCESS_H

#include <vector>
#include <string>

using namespace std;

class XT_PreProcess
{
private:
    inline bool is_invalid_record(string &);
public:
    XT_PreProcess();

    vector<string> clean_size_mark(vector<string> &);
    vector<string> clean_empty_function_mark(vector<string> &);
    vector<string> clean_nonempty_function_mark(vector<string> &);

    static vector<string> add_mem_size_info(vector<string> &);
};
#endif