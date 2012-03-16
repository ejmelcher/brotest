@load base/frameworks/notice

@load ./extract
@load ./hash
@load ./sha-hash

module VirusTotal;

export {
	redef enum Notice::Type += { Match };

	redef enum FileAnalysis::Action += { ACTION_HASH_MATCH };
	
	type Results: record {
		sent_file: bool                    &default=F;
		scan_date: string                  &optional;
		permalink: string                  &optional;
		hits:      table[string] of string &optional;
	};
	
	## This is your VirusTotal API key and *must* be supplied for this plugin to work.
	const api_key = "" &redef;
	
	## Define the number of queries per minute that your user can make.
	const queries_per_minute = 4 &redef;
	
	global report: event(f: FileAnalysis::Info, report: VirusTotal::Results);
}

global actions: set[FileAnalysis::Action] = {FileAnalysis::ACTION_HASH_MD5};
redef FileAnalysis::action_dependencies += { [ACTION_HASH_MATCH] = actions };

# Help abide by the virus total query limits
global query_limiter: set[string] &create_expire=1min;

type VTVal: record {
	s: string;
};

global file_map: table[string] of FileAnalysis::Info = {};

event VirusTotal::line(desc: Input::EventDescription, tpe: Input::Event, s: string) {
	local result: Results;
	result$hits = table();
	local sha1 = "";
	local md5 = "";
	
	# The data from virus total is a single line long so we remove the input right away.
	Input::remove(desc$name);
	
	# I'm parsing JSON this way.  Kill me now.
	local parts = split(s, / ?\{/ | /\}, /);
	for ( i in parts )
		{
		if ( /\"detected\": true/ in parts[i] )
			{
			local hit_parts = split(parts[i], /result\": \"/ | /\", \"update/);
			local whatever = gsub(parts[i-1], /[\":]/, "");
			result$hits[whatever] = hit_parts[2];
			}
		if ( /permalink/ in parts[i] )
			{
			local scan_parts = split(parts[i], /\"/);
			if ( 2 in scan_parts && scan_parts[2] == "permalink" )
				result$permalink = scan_parts[4];
			if ( 16 in scan_parts && scan_parts[16] == "scan_date" )
				result$scan_date = scan_parts[18];
			if ( 6 in scan_parts && scan_parts[6] == "sha1" )
				sha1 = scan_parts[8];
			if ( 36 in scan_parts && scan_parts[36] == "md5" )
				md5 = scan_parts[38];
			}
		}
	
	if ( desc$name in file_map )
		event VirusTotal::report(file_map[desc$name], result);
	
	delete file_map[desc$name];
}

event add_vt_input(f: FileAnalysis::Info, name: string)
	{
	Input::add_event([$name=name, 
	                  $source=fmt("%s.vt_result", f$md5),
	                  $fields=VTVal,
	                  $ev=VirusTotal::line,
	                  $reader=Input::READER_RAW, $mode=Input::MANUAL]);
	}

event FileAnalysis::trigger(f: FileAnalysis::Info, trig: FileAnalysis::Trigger)
	{
	if ( trig == FileAnalysis::IDENTIFIED_MD5 &&
	     api_key != "" &&
	     ACTION_HASH_MATCH in f$actions && 
	     # TODO: make this stop throwing out queries if they'd cross the limit.
	     |query_limiter| < queries_per_minute )
		{
		local cmd = fmt("curl -s -o %s.vt_result --data resource=%s --data apikey=%s https://www.virustotal.com/vtapi/v2/file/report", f$md5, f$md5, VirusTotal::api_key);
		system(cmd);
		
		local name = unique_id("vt_result");
		file_map[name] = f;
		# This will automatically be deleted, so we're done with it.
		add query_limiter[name];
		
		schedule 3sec { add_vt_input(f, name) };
		}
	}


event VirusTotal::report(f: FileAnalysis::Info, report: VirusTotal::Results)
	{
	local downloader: addr;
	for ( cid in f$cids )
		{
		# TODO: we're assuming the downloader is the orig for now.  this isn't exactly correct.
		downloader = cid$orig_h;
		}
	
	NOTICE([$note=VirusTotal::Match,
	        $msg=fmt("A file with md5sum matched %d engines on VirusTotal", |report$hits|),
	        $src=downloader]);
	}
