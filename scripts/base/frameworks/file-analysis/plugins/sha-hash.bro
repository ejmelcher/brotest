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

event sha_line(desc: Input::EventDescription, tpe: Input::Event, s: string)
	{
	# The data from shasum is a single line long so we remove the input right away.
	Input::remove(desc$name);
	# Remove the results file from disk.
	system(fmt("unlink %s", desc$source));

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
