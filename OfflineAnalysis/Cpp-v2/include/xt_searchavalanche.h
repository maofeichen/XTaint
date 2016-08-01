#ifndef XT_SEARCHAVALANCHE_H
#define XT_SEARCHAVALANCHE_H

#include "xt_data.h"
#include <string>
#include <vector>

struct Buffer
{
	unsigned long beginAddr;
	unsigned int size;
};

struct FunctionCallBuffer
{
	std::string callMark;
	std::string callSecMark;
	std::string retMark;
	std::string retSecMark;

	Buffer buffer;	
};

// Avalanche effect result
// All bytes of buffer in can propagate to all bytes of buffer out
struct AvalancheEffectResult
{
	FunctionCallBuffer in;
	FunctionCallBuffer out;
};

class SearchAvalanche
{
private:
	std::vector<Func_Call_Cont_Buf_t> m_vFuncCallContBuf;

	std::vector<FunctionCallBuffer> getFunctionCallBuffer(std::vector<Func_Call_Cont_Buf_t> v);	
public:
	SearchAvalanche();
	// ~SearchAvalanche();
	SearchAvalanche(std::vector<Func_Call_Cont_Buf_t> v_funcCallContBuf);

	void searchAvalanche();
};
#endif