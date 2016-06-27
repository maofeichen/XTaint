#ifndef XT_LIVENESS
#define XT_LIVENESS

#include <string>
#include <vector>

using namespace std;

class XT_Liveness
 {
 private:
    static vector<string> analyze_function_alive_buffer(vector<string> &);
 public:
     XT_Liveness();

     static std::vector<std::string> analyze_alive_buffer(std::vector<std::string> &);
     
 }; 
#endif