#include <fstream>
#include <iostream>
#include <vector>
#include "xt_file.h"

XT_File::XT_File(std::string path)
{
    path_r = path;
}

std::vector<std::string> XT_File::read()
{
    std::ifstream xt_file(path_r.c_str() );
    std::vector<std::string> v;
    std::string line;

    if(xt_file.is_open() ){
        while(getline(xt_file, line) )
            v.push_back(line);
    }
    else
        std::cout << "error open file: " << path_r << std::endl;
    xt_file.close();

    // std::cout << "read file: " << path_r << std::endl;
    // for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
    //     std::cout << *it << std::endl;

    return v;
}

void XT_File::write(string p, vector<string> &v)
{
    ofstream f(p.c_str());

    if(f.is_open()){
        for(vector<string>::iterator it = v.begin(); it != v.end(); ++it)
            f << *it <<'\n';

        f.close();
    }
    else
        cout << "error open file: " << p << endl;
}

