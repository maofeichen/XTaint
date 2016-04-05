// xt_file.cc - handles file related components

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "xt_file.h"

std::vector<std::string> XTFile::Read()
{
    std::ifstream xt_log(path_);
    std::vector<std::string> v;
    std::string line;
    
    if(xt_log.is_open() ){
        while(getline(xt_log, line) )
            v.push_back(line);
    } else
        std::cout << "error open file" << std::endl;
    xt_log.close();

    std::cout << "xtant log: " << std::endl;
    for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
        std::cout << *it << std::endl; 

    return v;   
}
