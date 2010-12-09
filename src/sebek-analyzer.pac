connection Sebek_Conn(bro_analyzer: BroAnalyzer)
	{
	upflow = Sebek_Flow;
	downflow = Sebek_Flow;
	};

flow Sebek_Flow
{
	datagram = Sebek3_PDU withcontext(connection, this);
	
	function process_sebek_message(m: Sebek3_PDU): bool
		%{
		double sb_time = double(${m.time_sec}) + double(${m.time_usec}) / 1e6;
		
		RecordVal* r = new RecordVal(sebek_hdr);
		r->Assign(0,  new Val(${m.magic},      TYPE_COUNT));
		r->Assign(1,  new Val(${m.ver},        TYPE_COUNT));
		r->Assign(2,  new Val(${m.type},       TYPE_COUNT));
		r->Assign(3,  new Val(${m.counter},    TYPE_COUNT));
		r->Assign(4,  new Val(sb_time,         TYPE_TIME));
		r->Assign(6,  new Val(${m.parent_pid}, TYPE_COUNT));
		r->Assign(7,  new Val(${m.pid},        TYPE_COUNT));
		r->Assign(8,  new Val(${m.uid},        TYPE_COUNT));
		r->Assign(9,  new Val(${m.fd},         TYPE_COUNT));
		r->Assign(10, new Val(${m.inode},      TYPE_COUNT));
		r->Assign(11, new StringVal(${m.com}.length(), (const char*) ${m.com}.begin()));
		
		bro_event_sebek_message(connection()->bro_analyzer(),
		                        connection()->bro_analyzer()->Conn(),
		                        r,
		                        new StringVal(${m.data}.length(), (const char*) ${m.data}.begin()));
		return true;
		%}
};

refine typeattr Sebek3_PDU += &let {
        proc_sebek_message = $context.flow.process_sebek_message(this);
};
