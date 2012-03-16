@load base/frameworks/input

module FileAnalysis;

export {
	redef enum Action += { ACTION_HASH_SHA1 };
	redef enum Trigger  += { IDENTIFIED_SHA1 };
	
	global sha_hash_actions: set[Action] = {ACTION_EXTRACT};
	redef action_dependencies += { [ACTION_HASH_SHA1] = sha_hash_actions };
	
	redef record Info += {
		sha1:    string &log &optional;
	};
}

type Val: record {
	s: string;
};

global sha_file_map: table[string] of Info = {};

event sha_line(tpe: Input::Event, s: string)
	{
	local parts = split(s, /[[:blank:]]+/);
	if ( |parts| == 2 )
		{
		local hash = parts[1];
		local filename = parts[2];
		if ( filename in sha_file_map )
			{
			sha_file_map[filename]$sha1 = hash;
			## Release the delay ticket.
			--sha_file_map[filename]$log_delay_tickets;
			
			event FileAnalysis::trigger(sha_file_map[filename], IDENTIFIED_SHA1);
			
			delete sha_file_map[filename];
			}
		}
	}

event add_sha_input(f: Info)
	{
	
	Input::add_event([$name=fmt("sha_hash::%s", get_file_name(f$disk_file)),
	                  $source=fmt("%s.sha_hash", get_file_name(f$disk_file)),
	                  $fields=Val,
	                  $ev=sha_line,
	                  $reader=Input::READER_RAW]);
	
	
	#Input::create_stream(FileAnalysis::SHASUM, [$source=fmt("%s.sha_hash", get_file_name(f$disk_file)), $reader=Input::READER_RAW, $mode=Input::REREAD]);
	#Input::add_eventfilter(FileAnalysis::SHASUM, [$name="whatever", $fields=Val, $ev=sha_line]);
	#Input::remove_eventfilter(FileAnalysis::SHASUM, "whatever");
	#Input::remove_stream(FileAnalysis::SHASUM);
	}

event FileAnalysis::linear_data_done(f: Info)
	{
	if ( ACTION_HASH_SHA1 in f$actions && f?$disk_file )
		{
		++f$log_delay_tickets;
		system(fmt("shasum \"%s\" > %s.sha_hash", get_file_name(f$disk_file), get_file_name(f$disk_file)));
		sha_file_map[get_file_name(f$disk_file)] = f;
		schedule 1sec { add_sha_input(f) };
		}
	}
