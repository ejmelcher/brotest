##! Types, errors, and fields for analyzing DHCP data.  A helper file
##! for DHCP analysis scripts.

module DHCP;

export {

	## Types of DHCP messages. See :rfc:`1533`.
	const message_types = {
		[1]  = "DHCP_DISCOVER",
		[2]  = "DHCP_OFFER",
		[3]  = "DHCP_REQUEST",
		[4]  = "DHCP_DECLINE",
		[5]  = "DHCP_ACK",
		[6]  = "DHCP_NAK",
		[7]  = "DHCP_RELEASE",
		[8]  = "DHCP_INFORM",
		[9]  = "DHCP_FORCERENEW", # RFC3203
		[10] = "DHCP_LEASEQUERY", # RFC4388
		[11] = "DHCP_LEASEUNASSIGNED", # RFC4388
		[12] = "DHCP_LEASEUNKNOWN", # RFC4388
		[13] = "DHCP_LEASEACTIVE", # RFC4388
		[14] = "DHCP_BULKLEASEQUERY", # RFC6926
		[15] = "DHCP_LEASEQUERYDONE", # RFC6926
		[16] = "DHCP_ACTIVELEASEQUERY", # RFC7724
		[17] = "DHCP_LEASEQUERYSTATUS", # RFC7724
		[18] = "DHCP_TLS", # RFC7724
	} &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };

}
