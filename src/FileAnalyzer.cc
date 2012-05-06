#include <algorithm>

#include "FileAnalyzer.h"
#include "Reporter.h"

File_Analyzer::File_Analyzer(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::File, conn)
	{
	//buffer_len = 0;
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	
	// No buffering for now, let's just pass the data straight through.
	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new Val(orig, TYPE_BOOL));
	vl->append(new StringVal(len, (const char*) data));
	ConnectionEvent(file_data, vl);
	
	return;
	}

void File_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();
	
	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	ConnectionEvent(file_done, vl);
	}