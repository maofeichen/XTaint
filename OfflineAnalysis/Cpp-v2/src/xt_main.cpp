#include <string>
#include <vector>
#include "xt_file.h"
#include "xt_preprocess.h"
using namespace std;

string XT_FILE_PATH = \
    "/home/mchen/Workspace/XTaint/OfflineAnalysis/Cpp-v2/test-file/";
string XT_FILE_NAME = \
    "test-aes-128-1B-all-identify-in-out-buffer-fake-data.txt";

int main(int argc, char const *argv[])
{
    vector<string> xt_log;
    
    XT_File xt_file(XT_FILE_PATH + XT_FILE_NAME);
    xt_log = xt_file.read();

    XT_PreProcess xt_preprocess;
    xt_log = xt_preprocess.clean_size_mark(xt_log);
    xt_log = xt_preprocess.clean_empty_function_mark(xt_log);

    return 0;
}