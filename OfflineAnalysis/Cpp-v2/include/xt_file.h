#ifndef XT_FILE_H
#define XT_FILE_H

#include <string>
#include <vector>

class XT_File
{
private:
    std::string m_path;
public:
    XT_File(std::string path);

    std::vector<std::string> read();
}; 
#endif