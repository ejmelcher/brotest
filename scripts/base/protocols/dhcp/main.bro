##! Analyzes DHCP traffic in order to log DHCP leases given to clients.
##! This script ignores large swaths of the protocol, since it is rather
##! noisy on most networks, and focuses on the end-result: assigned leases.
##!
##! If you'd like to track known DHCP devices and to log the hostname
##! supplied by the client, see
##! :doc:`/scripts/policy/protocols/dhcp/known-devices-and-hostnames.bro`.

@load ./utils.bro

module DHCP;

export {
	redef enum Log::ID += { LOG };

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts:          time        &log;
		## A series of unique identifiers of the connections over which 
		## DHCP is occurring.  This behavior with multiple connections is
		## unique to DHCP because of the way it uses broadcast packets
		## on local networks.
		uids:        set[string] &log;
		## Client's hardware address.
		mac:         string      &log &optional;
		client_name: string      &log &optional;
		## Client's actual assigned IP address.
		assigned_ip: addr        &log &optional;
		## IP address lease interval.
		lease_time:  interval    &log &optional;

		software:    string      &log &optional;
	};

	type TransferData: record {
		mac: string &optional;
		assigned_ip: addr &optional;
		lease_time: interval &optional;
		client_name: string &optional;
		software:    string &optional;
	};

	global transfer_data: event(ts: time, uid: string, msg: dhcp_msg, data: TransferData);

	## Event that can be handled to access the DHCP
	## record as it is sent on to the logging framework.
	global log_dhcp: event(rec: Info);
}

# Add the dhcp info to the connection record.
redef record connection += {
	dhcp: Info &optional;
};

# 67/udp is the server's port, 68/udp the client.
const ports = { 67/udp, 68/udp };
redef likely_server_ports += { 67/udp };

event bro_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, [$columns=Info, $ev=log_dhcp, $path="dhcp"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

# This is where the data is stored as it's centralized. All data for a log must 
# arrive within the expiration interval if it's to be logged fully.
global join_data: table[count] of Info = table() &create_expire=15secs;

event DHCP::transfer_data(ts: time, uid: string, msg: dhcp_msg, data: TransferData) &priority=5
	{
	if ( msg$xid !in join_data )
		join_data[msg$xid] = Info($ts=ts, $uids=set(uid));

	local info = join_data[msg$xid];
	if ( uid !in info$uids )
		add info$uids[uid];

	if ( data?$mac )
		info$mac = data$mac;

	if ( data?$assigned_ip )
		info$assigned_ip = data$assigned_ip;

	if ( data?$lease_time )
		info$lease_time = data$lease_time;

	if ( data?$client_name )
		info$client_name = data$client_name;

	if ( data?$software )
		info$software = data$software;
	}

event DHCP::transfer_data(ts: time, uid: string, msg: dhcp_msg, data: TransferData) &priority=-5
	{
	local info = join_data[msg$xid];
	if ( info?$lease_time )
		Log::write(LOG, info);
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string) &priority=5
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string)
	{
	print msg;
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData($client_name=host_name));
	}

event dhcp_decline(c: connection, msg: dhcp_msg, host_name: string)
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &priority=5
	{
	#local info: Info;
	#info$ts          = network_time();
	#info$id          = c$id;
	#info$uid         = c$uid;
	#info$lease_time  = lease;
	#info$trans_id    = msg$xid;

	#if ( msg$h_addr != "" )
	#	info$mac = msg$h_addr;

	local assigned_ip: addr;
	if ( reverse_ip(msg$yiaddr) != 0.0.0.0 )
		assigned_ip = reverse_ip(msg$yiaddr);
	else
		assigned_ip = c$id$orig_h;

	event DHCP::transfer_data(network_time(), 
	                          c$uid, msg, 
	                          TransferData($assigned_ip=assigned_ip,
	                                       $lease_time=lease,
	                                       $mac=msg$h_addr));
	}

event dhcp_nak(c: connection, msg: dhcp_msg, host_name: string)
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}

event dhcp_release(c: connection, msg: dhcp_msg, host_name: string)
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string)
	{
	event DHCP::transfer_data(network_time(), c$uid, msg, TransferData());
	}
