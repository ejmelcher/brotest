#include "Sebek-binpac.h"
#include "TCP_Reassembler.h"

Sebek_Analyzer_binpac::Sebek_Analyzer_binpac(Connection* conn)
	: Analyzer(AnalyzerTag::SEBEK_BINPAC, conn)
	{
	interp = new binpac::Sebek::Sebek_Conn(this);
	did_session_done = 0;
	//ADD_ANALYZER_TIMER(&Sebek_Analyzer_binpac::ExpireTimer,
	//              network_time + Sebek_session_timeout, 1, TIMER_Sebek_EXPIRE);
	}

Sebek_Analyzer_binpac::~Sebek_Analyzer_binpac()
	{
	delete interp;
	}

void Sebek_Analyzer_binpac::Done()
	{
	Analyzer::Done();
	
	if ( ! did_session_done )
		Event(udp_session_done);
	}

void Sebek_Analyzer_binpac::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}
