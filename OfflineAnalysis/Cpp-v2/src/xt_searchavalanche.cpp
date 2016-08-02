#include "xt_flag.h"
#include "xt_searchavalanche.h"
#include "xt_util.h"

#include <cassert>
#include <iostream>

#define DEBUG 1

using namespace std;

SearchAvalanche::SearchAvalanche(){}
SearchAvalanche::SearchAvalanche(vector<Func_Call_Cont_Buf_t> v_funcCallContBuf,
								 vector<Rec> logAesRec)
{
	m_vFuncCallContBuf = v_funcCallContBuf;
	m_logAesRec = logAesRec;
}

void SearchAvalanche::searchAvalanche()
{
	vector<FunctionCallBuffer> v_functionCallBuffer;

	// for (auto s : m_vFuncCallContBuf){
	// 	cout << "Call Mark: " << s.call_mark << endl;
	// 	cout << "Ret Mark: " << s.ret_mark << endl;
	// 	for(auto t : s.cont_buf){
	// 		cout << "Begin Addr: " << t.begin_addr << endl;
	// 		cout << "Size: " << t.size << endl;
	// 	}
	// }

	v_functionCallBuffer = getFunctionCallBuffer(m_vFuncCallContBuf);

	// cout << "Number of continuous buffer: " << v_functionCallBuffer.size() << endl;
	// for(auto s : v_functionCallBuffer){
	// 	cout << "Call Mark: " << s.callMark << endl;
	// 	cout << "Sec Call Mark: " << s.callSecMark << endl;
	// 	cout << "Ret Mark: " << s.retMark << endl;
	// 	cout << "Sec Ret Mark: " << s.retSecMark << endl;
	// 	cout << "Buffer Begin Addr: " << s.buffer.beginAddr << endl;
	// 	cout << "Buffer Size: " << s.buffer.size << endl;
	// }

	vector<FunctionCallBuffer>::iterator in = v_functionCallBuffer.begin();
	for(; in != v_functionCallBuffer.end(); ++in){
		// if NOT kernel address and larger than 8 bytes
		if(in->buffer.size >= BUFFER_LEN && 
		   !isKernelAddress(in->buffer.beginAddr) ){

			vector<FunctionCallBuffer>::iterator out = in + 1;
			for(; out != v_functionCallBuffer.end(); ++out){
				if(out->buffer.size >= BUFFER_LEN){
					// search avalanche effect between in and out continuous buffer
					searchAvalancheBetweenInAndOut(*in, *out);
				}
			} // end inner for
		}
	} // end outter for
}

inline string SearchAvalanche::getInsnAddr(unsigned int &idx, vector<Rec> &vRec)
{
	unsigned int i = idx;
	while(i > 0){
		if(vRec[i].isMark &&
           XT_Util::equal_mark(vRec[i].regular.src.flag, flag::XT_INSN_ADDR) )
			return vRec[i].regular.src.addr;
		i--;
   }
   return "";
}

// Is the hardcode correct?
inline bool SearchAvalanche::isKernelAddress(unsigned int addr)
{
	if(addr > KERNEL_ADDR)
		return true;
	else
		return false;
}

inline bool SearchAvalanche::isMarkMatch(string &mark, Rec &r)
{
	vector<string> vMark;

	vMark = XT_Util::split(mark.c_str(), '\t');
	if(vMark[0] == r.regular.src.flag && 
	   vMark[1] == r.regular.src.addr && 
	   vMark[2] == r.regular.src.val)
		return true;
	else return false;
}

// Determines if the given address is in the range of given node
// !!! Notice it MUST be < (NOT <= ) 
inline bool SearchAvalanche::isInRange(unsigned long &addr, Node &node)
{
	if(addr >= node.i_addr && addr < node.i_addr + node.sz / BIT_TO_BYTE)
		return true;
	else return false;
}

NodePropagate SearchAvalanche::initialBeginNode(FunctionCallBuffer &buf, 
												unsigned long &addr,
												vector<Rec> &logRec)
{
	NodePropagate s;
	Node node;
	bool isFound;
	int functionCallIdx = 0;
	unsigned int recordIdx = 0;

	// locate the function call position
	vector<Rec>::iterator it = logRec.begin();
	for(; it != logRec.end(); ++it){
		if(it->isMark){
			if(isMarkMatch(buf.callMark, *it) && 
			   isMarkMatch(buf.callSecMark, *(it + 1) ) ){
				functionCallIdx = it - logRec.begin();
				break;
			}
		}
	}

#ifdef DEBUG
	// functionCallIdx is the index of callMark in logRec vector
	if(functionCallIdx != 0)
		cout << "Function Call Idx: " << functionCallIdx << endl;
#endif

	if(functionCallIdx != 0){
		vector<Rec>::iterator it = logRec.begin() + functionCallIdx;
		for(; it != logRec.end(); ++it){
			if(!it->isMark){
				if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_LD) ){
					if(isInRange(addr, it->regular.src) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				} else if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_ST) ){
					if(isInRange(addr, it->regular.dst) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				}
			} // end if !it->isMark
		}
	}

	assert(isFound == true);
	if(isFound){
		if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_LD) ){
			node = logRec[recordIdx].regular.src;
			s.isSrc = true;
			s.id = recordIdx * 2;
		} else if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_ST) ){
			node = logRec[recordIdx].regular.dst;
			s.isSrc = false;
			s.id = recordIdx * 2 + 1;
		}
		s.parentId	= 0;
		s.layer		= 0;
		s.pos 		= recordIdx;
		s.insnAddr 	= getInsnAddr(recordIdx, logRec);
		s.n.flag 	= node.flag;
		s.n.addr 	= node.addr;
		s.n.val 	= node.val;
		s.n.i_addr 	= node.i_addr;
		s.n.sz 		= node.sz;
	}

	return s;
}

// Transfers Func_Call_Cont_Buf_t to FunctionCallBuffer.
// In Func_Call_Cont_Buf_t, each pair of call and ret mark may have multiple
// continuous buffers.
// But in FunctionCallBuffer, each pair of call and ret mark only have one
// continous buffer, even there might be repeated marks in the results.
vector<FunctionCallBuffer> SearchAvalanche::getFunctionCallBuffer(vector<Func_Call_Cont_Buf_t> &v)
{
	vector<FunctionCallBuffer> v_new;
	FunctionCallBuffer f;

	for(auto s : v){
		for(auto t : s.cont_buf){
			f.callMark = s.call_mark;
			f.callSecMark = s.sec_call_mark;
			f.retMark = s.ret_mark;
			f.retSecMark = s.sec_ret_mark;
			f.buffer.beginAddr = t.begin_addr;
			f.buffer.size = t.size;

			v_new.push_back(f);
		}
	}
	return v_new;
}

void SearchAvalanche::searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	NodePropagate s;
	unsigned int inBytes;
	unsigned long inBeginAddr;

#ifdef DEBUG
	cout << "Input buffer: " << endl;
	cout << "Call Mark: " << in.callMark << '\t';
	cout << "Sec Call Mark: " << in.callSecMark << endl;
	cout << "Ret Mark: " << in.retMark << '\t';
	cout << "Sec Ret Mark: " << in.retSecMark << endl;
	cout << "Input Addr: " << hex << in.buffer.beginAddr << '\t';
	cout << "Input Size: " << in.buffer.size << endl;

	cout << "Output buffer: " << endl;
	cout << "Call Mark: " << out.callMark << '\t';
	cout << "Sec Call Mark: " << out.callSecMark << endl;
	cout << "Ret Mark: " << out.retMark << '\t';
	cout << "Sec Ret Mark: " << out.retSecMark << endl;
	cout << "Output Addr: " << hex << out.buffer.beginAddr << '\t';
	cout << "Output Size: " << out.buffer.size << endl;
#endif

	inBytes = in.buffer.size / BIT_TO_BYTE;
	inBeginAddr = in.buffer.beginAddr;
	for(int byteIndex = 0; byteIndex < inBytes; byteIndex++){
		s = initialBeginNode(in, inBeginAddr, m_logAesRec);
		inBeginAddr++;
	}
}