#include <string>
#include "xt_file.h"

using namespace std;

string XT_FILE_PATH = \
    "/home/mchen/Workspace/XTaint/OfflineAnalysis/Cpp-v2/test-file/";
string XT_FILE_NAME = \
    "test-aes-128-1B-all-identify-in-out-buffer-fake-data.txt";

int main(int argc, char const *argv[])
{
    XT_File xt_file(XT_FILE_PATH + XT_FILE_NAME);
    xt_file.read();

    return 0;
}