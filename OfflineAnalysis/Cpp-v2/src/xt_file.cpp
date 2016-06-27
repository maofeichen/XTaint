#include <fstream>
#include <iostream>
#include <vector>
#include "xt_file.h"

XT_File::XT_File(std::string path)
{
    m_path = path;
}

std::vector<std::string> XT_File::read()
{
    std::ifstream xt_file(m_path.c_str() );
    std::vector<std::string> v;
    std::string line;

    if(xt_file.is_open() ){
        while(getline(xt_file, line) )
            v.push_back(line);
    }
    else
        std::cout << "error open file: " << m_path << std::endl;
    xt_file.close();

    // std::cout << "read file: " << m_path << std::endl;
    // for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
    //     std::cout << *it << std::endl;

    return v;
}

