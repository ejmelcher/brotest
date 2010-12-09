
#ifndef Sebek_binpac_h
#define Sebek_binpac_h

#include "UDP.h"
#include "TCP.h"

#include "sebek_pac.h"

class Sebek_Analyzer_binpac : public Analyzer {
public:
	Sebek_Analyzer_binpac(Connection* conn);
	virtual ~Sebek_Analyzer_binpac();
	
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
	                                int seq, const IP_Hdr* ip, int caplen);
	
	static Analyzer* InstantiateAnalyzer(Connection* conn)
	        { return new Sebek_Analyzer_binpac(conn); }
	
	static bool Available()
	        { return true; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);
	
	int did_session_done;
    
	binpac::Sebek::Sebek_Conn *interp;
};

#endif
