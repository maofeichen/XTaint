/*
 * file: xt_utils.cpp
 */

#include <iostream>
#include "xt_utils.h"

using namespace std;

vector<string> split(const char *s, char c)
{
    vector<string> r;

    do {
        const char *b = s;
        while(*s != c && *s)
            s++;

        r.push_back(string(b, s) );
    } while (*s++ != 0);
    
    // cout << "parse string to: " << r.size() << " tokens" << endl;
    // for(vector<string>::iterator i = r.begin(); i != r.end(); ++i){
    //     cout << *i << endl;
    // }

    return r;
}
