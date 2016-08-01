#include "xt_searchavalanche.h"
#include <iostream>
using namespace std;

SearchAvalanche::SearchAvalanche(){}
SearchAvalanche::SearchAvalanche(std::vector<Func_Call_Cont_Buf_t> v_funcCallContBuf)
{
	m_vFuncCallContBuf = v_funcCallContBuf;
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
		vector<FunctionCallBuffer>::iterator out = in + 1;
		for(; out != v_functionCallBuffer.end(); ++out){
			// search avalanche effect between in and out continuous buffer
		}
	}
}

// Transfers Func_Call_Cont_Buf_t to FunctionCallBuffer.
// In Func_Call_Cont_Buf_t, each pair of call and ret mark may have multiple
// continuous buffers.
// But in FunctionCallBuffer, each pair of call and ret mark only have one
// continous buffer, even there might be repeated marks in the results.
vector<FunctionCallBuffer> SearchAvalanche::getFunctionCallBuffer(vector<Func_Call_Cont_Buf_t> v)
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