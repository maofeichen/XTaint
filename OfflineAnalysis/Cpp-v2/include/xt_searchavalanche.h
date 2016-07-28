#ifndef XT_SEARCHAVALANCHE_H
#define XT_SEARCHAVALANCHE_H

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
	~SearchAvalanche();

	AvalancheEffectResult searchAvalanche(FunctionCallBuffer &in, FunctionCallBuffer &out);
};
#endif