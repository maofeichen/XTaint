// xt_file.h - handles file related components

#ifndef XT_FILE_H_
#define XT_FILE_H_

#include <string>
#include <vector>

// Handles file related compnonets, such as open, etc.
class XTFile
{
private:
    char *path_;

public:
    XTFile(char *path){
        path_ = path;
    }
	
    // Opens XTaint log and returns a vector contains all entries
    std::vector<std::string> Read();
};

#endif