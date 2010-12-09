type Sebek3_PDU = record {
	magic       : uint32;
	ver         : uint16 &check(ver == 3);
	type        : uint16;
	counter     : uint32;
	time_sec    : uint32;
	time_usec   : uint32;
	parent_pid  : uint32;
	pid         : uint32;
	uid         : uint32;
	fd          : uint32;
	inode       : uint32;
	com         : bytestring &length=12;
	data_len    : uint32;
	data        : bytestring &length=data_len;
} &byteorder = bigendian;
