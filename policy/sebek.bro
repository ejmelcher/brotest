redef capture_filters += { ["sebek"] = "port 100 and udp" };

global sebek_ports = { 80/udp } &redef;
redef dpd_config += { [ANALYZER_SEBEK_BINPAC] = [$ports = sebek_ports] };

module Sebek;

event sebek_message(c: connection, hdr: sebek_hdr, data: string)
	{
	print data;
	}
