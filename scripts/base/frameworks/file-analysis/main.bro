module FileAnalysis;

export {
	redef enum Log::ID += { LOG };
	
	type Trigger: enum {
		IDENTIFIED_NEW_FILE,
		IDENTIFIED_FILE_DONE,
		IDENTIFIED_MIME,
		IDENTIFIED_BOF,
		IDENTIFIED_EOD,
	};
	
	type Action: enum {
		ACTION_CALC_ENTROPY,
		ACTION_BUFFER,
	};
	
	type DataBuffer: record {
		## Byte offset into the file that this data chunk begins at.
		offset: count;
		
		## The data contained in the buffer.  It's an optional
		## field because this chunk may not have actually been 
		## seen and this buffer record may just be a placeholder
		## to indicate a missed chunk.
		data: string &optional;
		
		## Size of this data buffer if the data field is absent. 
		## This field will be set if this chunk is a missing chunk
		## and it indicates the amount of data missing.
		len: count;
	};
	
	## The number of bytes at the beginning of each file that will
	## be buffered by default.
	const default_buffer_beginning_bytes = 0 &redef;
	const default_buffer_reassembly_size = 1024*1024 &redef; # 1meg reassembly buffer!
	#const min_chunk_size = 1000;
	
	## No plugins can take longer than this to return if they
	## want to include data into the file analysis log.
	const max_logging_delay = 15secs &redef;
	
	type Info: record {
		## The internal identifier used while this file was being tracked.
		fid:  string &log;
		
		## Protocol this file was transferred over.
		protocol: string &log &optional;
		
		## Parent file.
		parent_fid: string &log &optional;
		
		## The connections over which the file chunks for this file were
		## transferred.  The normal case is a single conn_id.
		uids: set[string] &log;
		cids: set[conn_id] &default=set();
		
		## The size of the file if known.
		size: count &optional &log;
		
		mime_type:    string &log &optional;
		
		## Extended key/value metadata about the file.
		metadata: table[string] of string &default=table();
		
		## Indicates whether or not the file was or will be transferred
		## linearly.
		linear: bool &default=F &log;
		linear_data_offset: count &default=0;
		
		actions: set[Action]  &log;
		
		## The maximum number of bytes actively allowed for file reassembly.
		## TODO: a notice should be generated when the allowed buffer size is spent.
		buffered_reassembly_bytes: count;
		
		## If data is supposed to be buffered, each
		## chunk of data will be stored in this vector.
		buffer: vector of DataBuffer &optional;
		buffered_bytes: count &default=0;
		
		## Tickets to delay logging this file.
		## This is used by plugins that need a short interval before they 
		## have their data collected for logging.
		delay_tickets: set[string] &default=set();
		
		## This is set to the network time when this file is first attempted
		## to be logged.  If it's not ready to be logged due to outstand log
		## delay tickets, it will be delayed up to bro:id:`max_logging_delay`.
		first_done_ts: time &optional;
		
		reassembly_buffer_overflow: bool &default=F;
		reassembled_data: bool &default=F;
		waiting_for_offset: count &default=0;
		first_usable_buffer: DataBuffer &optional;
		done: bool &default=F;
	};
	
	type PolicyItem: record {
		## The "thing" that makes this policy item try to apply to a particular
		## file.
		trigger: Trigger;
		
		## Predicate to determine if the action for the current item should 
		## be applied to this file.
		pred:      function(rec: Info): bool &optional;
		
		## Action to take with the file.
		action:    Action &optional;
		
		## Use this if multiple actions are to be applied with a single PolicyItem.
		actions:   set[Action] &optional;
		
		## Indicate a maximum number of bytes to buffer for reassembly
		buffer_bytes: count &optional;
		
		## Indicate a maximum numbe of bytes to assemble into a string at the beginning of each file.
		buffer_beginning: bool &default=F;
	};
	
	const policy: set[PolicyItem] = {} &redef;
	
	## Defines dependencies of actions.
	const action_dependencies: table[Action] of set[Action] = {} &redef;
	
	## Used to send data from protocol analysis scripts into the file 
	## analysis framework.
	##
	## id: A unique identifier for any particular file.  It's used to tie 
	##     the individual chunks of data together into a single file.
	##
	## offset: The byte offset into the file where the data being given begins.
	##
	## data: The actual file data.
	global send_data: function(f: Info, protocol: string, offset: count, data: string);

	## Indicate the end of data for a file.
	global send_EOD: function(f: Info);
	
	global send_conn: function(f: Info, c: connection);
	global send_size: function(f: Info, size: count);
	global send_metadata: function(f: Info, key: string, val: string);
	
	global trigger: event(f: Info, trig: Trigger);
	
	global get_file: function(id: string): Info;
	global file_data: event(id: string, key: string, val: string);
	
	## This event can be used by the plugins to get linear data for the
	## file represented.  No offset for the data is given because all of
	## the data will be passed through linearly based on the fragmentation 
	## of the transfer and the limits of the reassembly buffer.
	global linear_data: event(f: Info, data: string);
	global linear_data_done: event(f: Info);
}

## This data structure is for tracking files that are transferred over protocols
## that use raw TCP sockets to transfer files and one TCP connection equates to 
## one file.
redef record connection += {
	file_analyzer_info: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(FileAnalysis::LOG, [$columns=Info]);
	}

# A variable for tracking all of the active files.
# It's indexed by the "id" used for the file so that it should remain globally unique.
global tracker: table[string] of Info = {} &read_expire=2mins &redef 
	&expire_func = function(the_table: table[string] of Info, index: any): interval
		{
		#print "expiring a file!";
		#print the_table[index];
		return 0secs;
		};

function get_file(id: string): Info
	{
	local fid = md5_hmac(id);
	if ( fid in tracker )
		{
		return tracker[fid];
		}
	else
		{
		local this_file: Info;
		
		this_file$fid = fid;
		this_file$buffered_reassembly_bytes = default_buffer_reassembly_size;
		this_file$actions=set();
		this_file$uids=set();
		this_file$cids=set();
		tracker[fid] = this_file;
		
		# Send the new file trigger
		event FileAnalysis::trigger(tracker[fid], IDENTIFIED_NEW_FILE);
		
		return tracker[fid];
		}
	}

function chunk_sorter(a: DataBuffer, b: DataBuffer): int
	{
	local ao = a$offset;
	local bo = b$offset;
	
	if ( ao == bo )
		return 0;
	else
		return ao < bo ? -1 : 1;
	}

function combine_buffers(a: DataBuffer, b: DataBuffer): DataBuffer
	{
	local db: DataBuffer;
	db$offset = a$offset;
	db$data = sub_bytes(a$data, 0, b$offset - a$offset) + b$data;
	db$len = |db$data|;
	return db;
	}

function reassemble_buffers(f: Info)
	{
	# Deal with a full reassembly buffer
	if ( f?$buffer )
		{
		delete f$first_usable_buffer;
		local buffered_bytes = 0;
		sort(f$buffer, chunk_sorter);
		local new_buffer: vector of DataBuffer = vector();
		local retained_last_buffer = F;
		
		#print "BEGIN REASSEMBLY!";
		for ( i in f$buffer )
			{
			local chunk = f$buffer[i];
			#print fmt("chunk in reassembly: linear data offset: %d -- chunk offset:%d -- chunk len:%d", f$linear_data_offset, chunk$offset, chunk$len);
			
			if ( f$linear_data_offset > chunk$offset + chunk$len )
				{
				#print "    throwing out a duplicate chunk";
				#print f$linear_data_offset;
				#print chunk$offset;
				#print chunk$len;
				# Throw out this buffer if linear data has already bypassed it
				# It's essentially redundant data at this point.
				f$buffered_bytes -= chunk$len;
				next;
				}
			
			if ( retained_last_buffer && 
			     new_buffer[|new_buffer|-1]$offset + new_buffer[|new_buffer|-1]$len >= chunk$offset )
				{
				#print "    combining chunks!";
				local combined_chunk_len = chunk$len + new_buffer[|new_buffer|-1]$len;
				chunk = combine_buffers(new_buffer[|new_buffer|-1], chunk);
				# Adjust the buffered bytes for any snipped/overlapping bytes.
				f$buffered_bytes -= combined_chunk_len - chunk$len;
				}
			
			#print fmt("    chunk offset:%d size:%d", chunk$offset, chunk$len);
			if ( chunk$offset <= f$linear_data_offset ||
			     f$linear_data_offset + chunk$len == f$size )
				{
				# Pull back on total buffered counter.
				if ( f$buffered_bytes > 0 )
					f$buffered_bytes -= chunk$len;
				
				f$reassembled_data = T;
				FileAnalysis::send_data(f, f$protocol, chunk$offset, chunk$data);
				f$reassembled_data = F;
				# Delete the buffer element after sending it to linear_data;
				# I avoid this for now by creating a new buffer of unused 
				# DataBuffers.
				#delete f$buffer[i]; <- Ack!  We need to be able to delete arbitrary elements!
				retained_last_buffer = F;
				}
			else
				{
				#print "    retain buffer";
				if ( chunk$offset == f$linear_data_offset )
					f$waiting_for_offset = chunk$offset+chunk$len;
				
				if ( retained_last_buffer )
					new_buffer[|new_buffer|-1] = chunk;
				else
					new_buffer[|new_buffer|] = chunk;
				
				if ( ! f?$first_usable_buffer || f$first_usable_buffer$offset > chunk$offset )
					f$first_usable_buffer = chunk;
				
				retained_last_buffer = F;
				}
			}
		f$buffer = new_buffer;
		}
	}

event FileAnalysis::file_done(f: Info) &priority=5
	{
	# Delete the file from the tracker right away since the record
	# will be maintained by direct value references from here on out.
	delete tracker[f$fid];
	
	if ( ! f?$first_done_ts )
		f$first_done_ts = network_time();
	
	if ( |f$delay_tickets| == 0 || f$first_done_ts+max_logging_delay < network_time() )
		Log::write(LOG, f);
	else
		schedule 1sec { FileAnalysis::file_done(f) };
	}

function send_data(f: Info, protocol: string, offset: count, data: string)
	{
	f$protocol = protocol;
	#print fmt("RECEIVING: offset:%d length:%d", offset, |data|);
	
	#if ( f$done )
	#	{
	#	print "extra data received?";
	#	return;
	#	}
	
	local local_data = data;
	# If the data overlaps with data already sent through linear_data, trim it.
	if ( offset < f$linear_data_offset && f$linear_data_offset < offset+|data| )
		{
		#print f$linear_data_offset;
		#print offset;
		#print |local_data|;
		#print fmt("    snipped From: %d To: %d", f$linear_data_offset - offset + 1, |local_data|);
		local_data = sub_bytes(local_data, f$linear_data_offset - offset + 1, |local_data|);
		offset += |data| - |local_data|;
		}
	else if ( offset < f$linear_data_offset && offset+|data| < f$linear_data_offset )
		{
		#print "    throwing out data since it has been bypassed";
		return;
		}
	
	#print fmt("    linear offset: %d - offset: %d - data len: %d", f$linear_data_offset, offset, |local_data|);
	if ( offset <= f$linear_data_offset || 
		 (f?$size && f$size == f$linear_data_offset+|local_data|) )
		{
		if ( f$linear_data_offset == 0 )
			event FileAnalysis::trigger(f, IDENTIFIED_BOF);
			
		if ( ! f?$mime_type )
			{
			f$mime_type = split1(identify_data(local_data, T), /;/)[1];
			event FileAnalysis::trigger(f, IDENTIFIED_MIME);
			}
		
		# Push the linear data offset forward.
		f$linear_data_offset += |local_data|;

		# Send the data to the linear_data event.
		event FileAnalysis::linear_data(f, local_data);
		
		# If the linear data offset has reached the full file size
		# we should send the event to indicate the end of linear data.
		#print fmt("    LINEAR OFFSET IS NOW %d AND FILE SIZE IS %d", f$linear_data_offset, f$size);
		if ( ! f?$first_done_ts && 
		     f?$size && f$linear_data_offset == f$size )
			{
			#f$done = T;
			event FileAnalysis::linear_data_done(f);
			}
		else if ( f?$first_usable_buffer )
			{
			reassemble_buffers(f);
			return;
			}
		
		}
	else if ( ! f$reassembled_data )
		{
		if ( ! f?$buffer )
			f$buffer = vector();
		
		local chunk: DataBuffer = [$offset=offset, $data=local_data, $len=|data|];
		f$buffer[|f$buffer|] = chunk;
		f$buffered_bytes += |local_data|;
		
		if ( ! f?$first_usable_buffer ||
		     f$first_usable_buffer$offset > chunk$offset )
			f$first_usable_buffer = chunk;
		
		#print fmt("    buffered bytes: %d buffered elements: %d", f$buffered_bytes, |f$buffer|);
		if ( f$first_usable_buffer$offset <= f$linear_data_offset ||
			 f$waiting_for_offset == offset )
			reassemble_buffers(f);
		return;
		}
	
	if ( f$buffered_bytes > f$buffered_reassembly_bytes )
		{
		f$reassembly_buffer_overflow = T;
		event FileAnalysis::file_done(f);
		}
	}

function send_EOD(f: Info)
	{
	reassemble_buffers(f);

	event FileAnalysis::trigger(f, IDENTIFIED_EOD);
	f$done = T;
	if ( ! f?$first_done_ts )
		event FileAnalysis::linear_data_done(f);
	}

function send_conn(f: Info, c: connection)
	{
	add f$uids[c$uid];
	add f$cids[c$id];
	}
	
function send_size(f: Info, size: count)
	{
	# TODO: should watch for this value to be set and watch for it 
	#       to change.  it could be worthy of a weird or notice.
	f$size = size;
	}
	
event FileAnalysis::trigger(f: Info, trig: Trigger) &priority=5
	{
	# TODO: optimize this
	for ( pi in policy )
		{
		if ( pi$trigger == trig && 
			 ( ! pi?$pred || pi$pred(f) ) )
			{
			local actions: set[Action];
			
			if ( pi?$action )
				actions = set(pi$action);
			else if ( pi?$actions )
				actions = pi$actions;
			
			for ( action in actions )
				{
				add f$actions[action];
				
				if ( action in action_dependencies )
					{
					for ( dep_action in action_dependencies[action] )
						{
						add f$actions[dep_action];
						# Make it stop!!!  This deals with dependencies of dependencies. :(
						for ( dep_dep_action in action_dependencies[action] )
							add f$actions[dep_dep_action];
						}
					}
				}
			}
		}
	}

@load ./plugins/hash
event FileAnalysis::linear_data_done(f: Info) &priority=-10
	{
	# The file must have at least one connection and some size 
	# associated with it before we are willing to log it.
	if ( (f$done || (f?$size && f$size > 0)) &&
		 |f$uids| > 0 )
		{
		f$size = f$linear_data_offset;
		event FileAnalysis::file_done(f);
		}
	}

event bro_done()
	{
	for ( fid in tracker )
		{
		#print tracker[fid];
		#event FileAnalysis::linear_data_done(tracker[fid]);
		}
	}
