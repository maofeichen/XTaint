#include <string>
#include <vector>
#include "xt_file.h"
#include "xt_liveness.h"
#include "xt_preprocess.h"
using namespace std;

const string XT_FILE_EXT = ".txt";
const string XT_FILE_PATH = \
    "/home/mchen/Workspace/XTaint/OfflineAnalysis/Cpp-v2/test-file/";
const string XT_RESULT_PATH = \
    "/home/mchen/Workspace/XTaint/OfflineAnalysis/Cpp-v2/test-result/";

const string XT_FILE_FAKE_DATA = \
    "test-aes-128-1B-all-identify-in-out-buffer-fake-data";
const string XT_FILE_AES = \
    "test-aes-128-1B-all-marks";

const string XT_PREPROCESS = \
    "-preprocess";
const string XT_ADD_SIZE_INFO = 
    "-add-size-info";
const string XT_ALIVE_BUF = 
    "-alive-buf";
const string CONT_BUF = "-cont-buf";

int main(int argc, char const *argv[])
{
    vector<string> xt_log_aes, xt_log_fake;
    vector<string> aes_alive_buf;
    vector<Func_Call_Cont_Buf_t> v_func_call_cont_buf;

    // aes xtaint log  
    XT_File xt_file_aes(XT_FILE_PATH + XT_FILE_AES + XT_FILE_EXT);
    xt_log_aes = xt_file_aes.read();

    // preprocess xtaint log
    XT_PreProcess xt_preprocess;
    xt_log_aes = xt_preprocess.clean_size_mark(xt_log_aes);
    xt_log_aes = xt_preprocess.clean_empty_function_mark(xt_log_aes);
    xt_log_aes = xt_preprocess.clean_nonempty_function_mark(xt_log_aes);
    xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_PREPROCESS + XT_FILE_EXT, xt_log_aes); 

    xt_log_aes = XT_PreProcess::add_mem_size_info(xt_log_aes);
    xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ADD_SIZE_INFO + XT_FILE_EXT, xt_log_aes);

    // buffer liveness analysis
    aes_alive_buf = XT_Liveness::analyze_alive_buffer(xt_log_aes);
    xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ALIVE_BUF + XT_FILE_EXT, aes_alive_buf); 

    // merge continues buffers
    v_func_call_cont_buf = XT_Liveness::merge_continue_buffer(aes_alive_buf);
    xt_file_aes.write_continue_buffer(XT_RESULT_PATH + XT_FILE_AES + CONT_BUF + XT_FILE_EXT, v_func_call_cont_buf);

    // fake data xtaint log
    // XT_File xt_file_fake(XT_FILE_PATH + XT_FILE_FAKE_DATA + XT_FILE_EXT);
    // xt_log_fake = xt_file_fake.read();
    // XT_Liveness::analyze_alive_buffer(xt_log_fake);

    return 0;
}