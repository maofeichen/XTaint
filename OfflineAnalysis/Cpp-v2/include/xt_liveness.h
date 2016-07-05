#ifndef XT_LIVENESS
#define XT_LIVENESS

#include <string>
#include <vector>

using namespace std;

class XT_Liveness
 {
 private:
    static const unsigned long STACK_BEGIN_ADDR = 0xb0000000;

    static inline bool is_mem_alive(unsigned long &, unsigned long &);
    static inline bool is_stack_mem_alive(unsigned long &, unsigned long &);
    static inline bool is_heap_mem_alive();

    static vector<string> analyze_function_alive_buffer(vector<string> &); // IGNORE
    static vector<string> analyze_alive_buffer_per_function(vector<string> &);
 public:
     XT_Liveness();

     static std::vector<std::string> analyze_alive_buffer(std::vector<std::string> &);
     
 }; 
#endif