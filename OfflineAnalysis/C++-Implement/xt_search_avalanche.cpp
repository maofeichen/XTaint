/**
 * xt_search_avalanche.cpp
 * Search avalanche buffers given a XTaint log.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "xt_flag.h"

using namespace std;

const char* XTLOG_PATH = \
    "./Test-File/test-aes-128-oneblock-sizemark-funcmark.txt";

vector<string> read_file(const char *);
vector<string> preprocess(vector<string> &);
vector<string> clean_size_mark(vector<string> &);
vector<string> clean_func_mark(vector<string> &);

int main(void)
{
    vector<string> xt_log_str;

    xt_log_str = read_file(XTLOG_PATH);
    xt_log_str = preprocess(xt_log_str);
}

vector<string> read_file(const char *fp)
{
    ifstream xt_log(fp);
    vector<string> q;
    string ln;
    
    if(xt_log.is_open() ){
        while(getline(xt_log, ln) )
            q.push_back(ln);
    } else
        cout << "error open file" << endl;
    xt_log.close();

    // cout << "orginal xtant log: " << endl;
    // for(vector<string>::iterator i = q.begin(); i != q.end(); ++i)
    //     cout << *i << endl; 

    return q;
}

vector<string> preprocess(vector<string> &v)
{
    vector<string> v_new;
    v_new = clean_size_mark(v);

    return v_new;
}

// v - contain xtaint record line by line
// if a pair of size mark, there is no records between, delete it
// return - new vector
vector<string> clean_size_mark(vector<string> &v)
{
    vector<string> v_new;
    string b, e;
    
    for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
        // if a size end mark
        if( (*i).substr(0,2).compare(XT_SIZE_END) == 0){
            e = *i;
            b = v_new.back();
            // if a match size begin mark
            if(b.substr(0,2).compare(XT_SIZE_BEGIN) == 0)
                if(b.substr(3, string::npos).compare(e.substr(3,string::npos) ) == 0 ){
                    v_new.pop_back();
                    continue;
                }
        }
        v_new.push_back(*i);
    }
    cout << "after clean size mark: " << endl;
    for(vector<string>::iterator i = v_new.begin(); i != v_new.end(); ++i)
        cout << *i << endl; 
    return v_new;
}

// v - contain xtaint record line by line
// if a pair of size mark, there is no records between, delete it
// return - new vector
vector<string> clean_func_mark(vector<string> v)
{}
