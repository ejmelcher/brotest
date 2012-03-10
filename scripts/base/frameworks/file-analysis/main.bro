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
		len: count &optional;
	};
	
	## The number of bytes at the beginning of each file that will
	## be buffered by default.
	const default_buffer_beginning_bytes = 0;
	const default_buffer_reassembly_size = 1024*1024; # 1meg reassembly buffer!

	type Info: record {
		## The internal identifier used while this file was being tracked.
		fid:  string &log;
		
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
		
		## The number of bytes of the beginning of a file to buffer for 
		## reassembly and "whole" searching.
		buffered_beginning_bytes: count;
		
		## The maximum number of bytes actively allowed for file reassembly.
		## TODO: a notice should be generated when the allowed buffer size is spent.
		buffered_reassembly_bytes: count;
		
		## If data is supposed to be buffered, each
		## chunk of data will be stored in this vector.
		buffer: vector of DataBuffer &optional;
		total_buffered_bytes: count &default=0;
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
	global send_data: function(id: string, offset: count, data: string);

	## Indicate the end of data for a file.
	global send_EOF: function(id: string);
	
	global send_conn: function(id: string, c: connection);
	global send_size: function(id: string, size: count);
	global send_metadata: function(id: string, key: string, val: string);
	
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
		
		this_file$buffered_beginning_bytes = default_buffer_beginning_bytes;
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

function chunk_sorter(a: DataBuffer, b: DataBuffer): bool
	{
	return a$offset < b$offset;
	}

function send_data(id: string, offset: count, data: string)
	{
	local fl = get_file(id);
	
	if ( (fl$buffered_beginning_bytes > 0 && offset < fl$buffered_beginning_bytes) ||
	     (fl$total_buffered_bytes < fl$buffered_reassembly_bytes && offset != fl$linear_data_offset) )
		{
		if ( ! fl?$buffer )
			fl$buffer = vector();
		
		fl$buffer[|fl$buffer|] = [$offset=offset, $data=data];
		fl$total_buffered_bytes += |data|;
		}
	
	if ( offset == 0 )
		{
		local mime_type = split1(identify_data(data, T), /;/)[1];
		if ( mime_type != "" )
			{
			fl$mime_type = mime_type;
			event FileAnalysis::trigger(fl, IDENTIFIED_MIME);
			}
			
		# Send the BOF trigger
		event FileAnalysis::trigger(fl, IDENTIFIED_BOF);
		}
	
	if ( offset <= fl$linear_data_offset )
		{
		local local_data = data;
		if ( offset != fl$linear_data_offset )
			local_data = sub_bytes(local_data, fl$linear_data_offset - offset, |local_data|+offset-fl$linear_data_offset);
		
		fl$linear_data_offset += |local_data|;
		event FileAnalysis::linear_data(fl, local_data);
		}
		
	# Deal with a full reassembly buffer
	if ( fl$total_buffered_bytes > fl$buffered_reassembly_bytes )
		{
		sort(fl$buffer, chunk_sorter);
		local new_buffer: vector of DataBuffer = vector();
		for ( i in fl$buffer )
			{
			local chunk = fl$buffer[i];
			#print chunk$offset;
			#print fl$linear_data_offset;
			#print "=====";
			if ( chunk$offset == fl$linear_data_offset )
				{
				event FileAnalysis::linear_data(fl, chunk$data);
				
				# Delete the buffer element after sending it to linear_data;
				# I avoid this for now by creating a new buffer of unused 
				# DataBuffers.
				#delete fl$buffer[i]; <- Ack!  We need to be able to delete arbitrary elements!
				
				# Pull back on total buffered by and push linear data offset forward.
				fl$total_buffered_bytes -= |chunk$data|;
				fl$linear_data_offset += |chunk$data|;
				
				# If the linear data offset has reached the full file size
				# we should send the event to indicate the end of linear data.
				if ( fl$linear_data_offset == fl$size-1 )
					event FileAnalysis::linear_data_done(fl);
				}
			else
				{
				# The current chunk didn't get passed to linear_data so we need
				# to keep it around.
				new_buffer[|new_buffer|] = chunk;
				}
			}
		fl$buffer = new_buffer;
		}
	
	# Check if the reassembly buffer is still full even after 
	if ( fl$total_buffered_bytes > fl$buffered_reassembly_bytes )
		{
		#print "reassembly buffer overflow";
		delete file_tracker[id];
		}
	}

function send_EOF(id: string)
	{
	local fl = get_file(id);
	event FileAnalysis::trigger(fl, IDENTIFIED_EOF);
	event FileAnalysis::linear_data_done(fl);
	delete file_tracker[id];
	}

function send_conn(id: string, c: connection)
	{
	local fl = get_file(id);
	add fl$uids[c$uid];
	add fl$cids[c$id];
	}
	
function send_size(id: string, size: count)
	{
	local fl = get_file(id);
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

event FileAnalysis::linear_data_done(f: Info) &priority=-10
	{
	Log::write(LOG, f);
	#delete file_tracker[f$fid];
	}

event bro_done()
	{
	for ( fid in file_tracker )
		{
		event FileAnalysis::linear_data_done(file_tracker[fid]);
		}
	}