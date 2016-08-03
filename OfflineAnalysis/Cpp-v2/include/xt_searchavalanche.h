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
public:
	SearchAvalanche();
	// ~SearchAvalanche();
	SearchAvalanche(std::vector<Func_Call_Cont_Buf_t> v_funcCallContBuf, 
					std::vector<Rec> logAesRec);
	void searchAvalanche();

private:
	const unsigned int 	BIT_TO_BYTE			= 8;
	const unsigned int 	BUFFER_LEN			= 64;
	const unsigned long KERNEL_ADDR			= 0xC0000000;
	const unsigned int 	VALID_AVALANCHE_LEN	= 8;

	inline std::string getInsnAddr(unsigned int &idx, std::vector<Rec> &vRec);
	inline bool isKernelAddress(unsigned int addr);
	inline bool isMarkMatch(std::string &mark, Rec &r);
	inline bool isInRange(unsigned long &addr, Node &node);
	inline bool isSameNode(NodePropagate &a, NodePropagate &b);

	std::vector<FunctionCallBuffer> getOutputAvalanche(std::unordered_set<Node, NodeHash> &propagateResult, 
													   FunctionCallBuffer &out);
	std::vector<FunctionCallBuffer> getFunctionCallBuffer(std::vector<Func_Call_Cont_Buf_t> &v);	
	NodePropagate initialBeginNode(FunctionCallBuffer &buf, unsigned long &addr, std::vector<Rec> &logRec);
	void searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, FunctionCallBuffer &out);

	std::vector<Func_Call_Cont_Buf_t> m_vFuncCallContBuf;
	std::vector<Rec> m_logAesRec;
};
#endif