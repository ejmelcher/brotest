module FileAnalysis;

export {
	redef enum Log::ID += { LOG };
	
	type Trigger: enum {
		IDENTIFIED_NEW_FILE,
		IDENTIFIED_FILE_DONE,
		IDENTIFIED_MIME,
		IDENTIFIED_BOF,
		IDENTIFIED_EOF,
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
	const min_chunk_size = 1000;
	
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
	};
	
	type PolicyItem: record {
		## The "thing" that makes this policy item try to apply to a particular
		## file.
		trigger: Trigger;
		
		## Predicate to determine if the action for the current item should 
		## be applied to this file.
		pred:      function(rec: Info): bool &optional;
		
		## Action to take with the file.
		action:    Action;
		
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
	global send_data: function(id: Info, protocol: string, offset: count, data: string);

	## Indicate the end of data for a file.
	global send_EOF: function(id: Info);
	
	global send_conn: function(id: Info, c: connection);
	global send_size: function(id: Info, size: count);
	global send_metadata: function(id: Info, key: string, val: string);
	
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

event bro_init() &priority=5
	{
	Log::create_stream(FileAnalysis::LOG, [$columns=Info]);
	}

# A variable for tracking all of the active files.
# It's indexed by the "id" used for the file so that it should remain globally unique.
global file_tracker: table[string] of Info = table();

function get_file(id: string): Info
	{
	if ( id in file_tracker )
		{
		return file_tracker[id];
		}
	else
		{
		local this_file: Info;
		
		# TODO: should probably do an optimization here and do this later.
		this_file$fid = md5_hash(id);
		
		this_file$buffered_reassembly_bytes = default_buffer_reassembly_size;
		this_file$actions=set();
		this_file$uids=set();
		this_file$cids=set();
		file_tracker[id] = this_file;
		
		# Send the new file trigger
		event FileAnalysis::trigger(file_tracker[id], IDENTIFIED_NEW_FILE);
		
		return file_tracker[id];
		}
	}

function chunk_sorter(a: DataBuffer, b: DataBuffer): int
	{
	local ao = a$offset;
	local bo = b$offset;
	
	if ( ao == bo )
		return 0;
	else
		return a$offset < b$offset ? -1 : 1;
	}

function combine_buffers(a: DataBuffer, b: DataBuffer): DataBuffer
	{
	local db: DataBuffer;
	db$offset = a$offset;
	db$data = sub_bytes(a$data, 0, b$offset - a$offset) + b$data;
	db$len = |db$data|;
	return db;
	}

function reassemble_buffers(fl: Info)
	{
	# Deal with a full reassembly buffer
	#if ( fl$buffered_bytes > fl$buffered_reassembly_bytes )
	if ( fl?$buffer )
		{
		#print "working with buffer";
		sort(fl$buffer, chunk_sorter);
		local new_buffer: vector of DataBuffer = vector();
		local kept_last_buffer = F;
		
		for ( i in fl$buffer )
			{
			local chunk = fl$buffer[i];
			#print fmt("in reassembly: %s -- linear data offset: %d -- chunk offset:%d -- chunk len:%d", fl$cids, fl$linear_data_offset, chunk$offset, chunk$len);
			
			if ( fl$linear_data_offset > chunk$offset + chunk$len )
				{
				# Throw out this buffer if linear data has already bypassed it
				# It's essentially redundant data at this point.
				fl$buffered_bytes -= chunk$len;
				#print "next!";
				next;
				}
				
			#print fmt("chunk length in reassembly buffer: %d -- chunk offset:%d", chunk$len, chunk$offset);
			
			if ( kept_last_buffer && 
			     new_buffer[|new_buffer|-1]$offset+new_buffer[|new_buffer|-1]$len >= chunk$offset )
				{
				#print fl$buffer[i-1]$len;
				#print chunk$len;
				
				#print "combining buffers!";
				chunk = combine_buffers(new_buffer[|new_buffer|-1], chunk);
				#print fl$buffer[i-1]$len;
				#print chunk$len;
				}
			
			if ( min_chunk_size <= chunk$len && chunk$offset == fl$linear_data_offset )
				{
				#print "reassembled!";
				# Pull back on total buffered counter.
				fl$buffered_bytes -= chunk$len;
				
				FileAnalysis::send_data(fl, fl$protocol, chunk$offset, chunk$data);
				#print "sent linear data";
				# Delete the buffer element after sending it to linear_data;
				# I avoid this for now by creating a new buffer of unused 
				# DataBuffers.
				#delete fl$buffer[i]; <- Ack!  We need to be able to delete arbitrary elements!
				kept_last_buffer = F;
				}
			else
				{
				if ( kept_last_buffer )
					new_buffer[|new_buffer|-1] = chunk;
				else
					# The current chunk didn't get passed to linear_data so we need
					# to keep it around.
					new_buffer[|new_buffer|] = chunk;
					
				#print "keeping the buffer";
				kept_last_buffer = T;
				}
			}
		fl$buffer = new_buffer;
		#print fl$buffer;
		}
	
	}

function send_data(id: Info, protocol: string, offset: count, data: string)
	{
	#local fl = get_file(id);
	local fl = id;
	
	if ( |data| > 1 )
		{
		#print "Got reassembled data!";
		#print fmt("linear data offset:%d -- offset:%d -- |data|:%d", fl$linear_data_offset, offset, |data|);
		}
		
	fl$protocol = protocol;
	
	if ( (min_chunk_size <= |data| && offset <= fl$linear_data_offset) || 
		 (fl?$size && fl$size == fl$linear_data_offset+|data|) )
		{
		local local_data = data;
		# If the data overlaps with data already sent through linear_data, trim it.
		if ( offset < fl$linear_data_offset )
			local_data = sub_bytes(local_data, fl$linear_data_offset - offset, |local_data|+offset-fl$linear_data_offset);
		
		if ( fl$linear_data_offset == 0 )
			event FileAnalysis::trigger(fl, IDENTIFIED_BOF);
			
		if ( ! fl?$mime_type )
			{
			fl$mime_type = split1(identify_data(data, T), /;/)[1];
			event FileAnalysis::trigger(fl, IDENTIFIED_MIME);
			}
		
		# Push the linear data offset forward.
		fl$linear_data_offset += |local_data|;
		
		# Send the data to the linear_data event.
		event FileAnalysis::linear_data(fl, local_data);

		# If the linear data offset has reached the full file size
		# we should send the event to indicate the end of linear data.
		if ( fl?$size && fl$linear_data_offset == fl$size )
			{
			event FileAnalysis::linear_data_done(fl);
			delete file_tracker[id$fid];
			}
		}
	#if ( fl$buffered_bytes < fl$buffered_reassembly_bytes && offset != fl$linear_data_offset )
	else
		{
		if ( ! fl?$buffer )
			fl$buffer = vector();
		
		fl$buffer[|fl$buffer|] = [$offset=offset, $data=data, $len=|data|];
		fl$buffered_bytes += |data|;
		
		if ( fl$buffered_bytes > min_chunk_size && offset <= fl$linear_data_offset )
			reassemble_buffers(fl);
		return;
		}
	
	# Check if the reassembly buffer is still full even after 
	if ( fl$buffered_bytes > fl$buffered_reassembly_bytes )
		{
		#print "reassembly buffer overflow";
		delete file_tracker[id$fid];
		}
		
	#print "";
	#print "";
	}

function send_EOF(id: Info)
	{
	#local fl = get_file(id);
	local fl = id;
	
	reassemble_buffers(fl);
	
	event FileAnalysis::trigger(fl, IDENTIFIED_EOF);
	event FileAnalysis::linear_data_done(fl);
	
	delete file_tracker[id$fid];
	}

function send_conn(id: Info, c: connection)
	{
	#local fl = get_file(id);
	local fl = id;
	add fl$uids[c$uid];
	add fl$cids[c$id];
	}
	
function send_size(id: Info, size: count)
	{
	#local fl = get_file(id);
	local fl = id;
	# TODO: should watch for this value to be set and watch for it 
	#       to change.  it could be worthy of a weird or notice.
	fl$size = size;
	}
	
event trigger(f: Info, trig: Trigger)
	{
	# TODO: optimize this
	for ( pi in policy )
		{
		if ( pi$trigger == trig && 
			 ( ! pi?$pred || pi$pred(f) ) )
			{
			add f$actions[pi$action];
			#print "matched a file analysis policy item!";
			#print f;
			if ( pi$action in action_dependencies )
				for ( dep_action in action_dependencies[pi$action] )
					add f$actions[dep_action];
			}
		}
	}

event FileAnalysis::linear_data(f: Info, data: string) &priority=10
	{
	# Push the lienar data offset forward.
	#f$linear_data_offset += |data|;
	# If the linear data offset has reached the full file size
	# we should send the event to indicate the end of linear data.
	#if ( f$linear_data_offset == f$size-1 )
	#	event FileAnalysis::linear_data_done(f);
	}

event FileAnalysis::linear_data_done(f: Info) &priority=-10
	{
	# The file must have at least one connection associated with it
	# before we are willing to log it.
	if ( |f$uids| > 0 )
		{
		f$size = f$linear_data_offset;
		Log::write(LOG, f);
		}
	}

#event bro_done()
#	{
#	for ( fid in file_tracker )
#		{
#		event FileAnalysis::linear_data_done(file_tracker[fid]);
#		}
#	}