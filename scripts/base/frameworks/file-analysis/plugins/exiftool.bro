@load base/frameworks/input

module FileAnalysis;

export {
	redef enum Action += { ACTION_EXIFTOOL };
	redef enum Trigger  += { IDENTIFIED_EXIFTOOL };
	
	#global exiftool_hash_actions: set[Action] = {ACTION_EXTRACT};
	#redef action_dependencies += { [ACTION_HASH_EXIFTOOL] = exiftool_hash_actions };
	
	redef record Info += {
		#exiftool:    string &log &optional;
		running_exiftool: bool &default=F;
		exiftool_data_fifo: file &optional;
		image_width: count &optional;
		image_height: count &optional;
	};

	type GifImage: record {
		width: count &optional;
		height: count &optional;
		frame_count: count &optional;
		animation_iterations: count &optional;
		has_color_map: bool &optional;
		color_resolution_depth: count &optional;
		bits_per_pixel: count &optional;
	};

}

type exiftoolVal: record {
	s: string;
};

global exiftool_file_map: table[string] of Info = {};

event exiftool_line(desc: Input::EventDescription, tpe: Input::Event, s: string)
	{
	if ( s == "}]" )
		{
		print "deleting the input!";
		Input::remove(desc$name);
		#system(fmt("rm -f %s.exiftool_fifo", f$fid));
		
		event FileAnalysis::trigger(exiftool_file_map[desc$name], IDENTIFIED_EXIFTOOL);
		delete exiftool_file_map[desc$name];
		
		return;
		}
		
	if ( desc$name !in exiftool_file_map )
		return;
	
	local f = exiftool_file_map[desc$name];
		
	
	#if ( /^  \"(File|Composite|ExifTool):/ in s )
	#	return;
	
	local parts = split(s, /\": /); #" <-  this is stupid and only because my color-izer is buggy
	if ( |parts| >= 2 )
		{
		local hash = parts[1];
		if ( desc$name in exiftool_file_map )
			{
			if ( parts[1] == "\"GIF:ImageWidth" )
				f$image_width = to_count(parts[2]);
			if ( parts[1] == "\"GIF:ImageHeight" )
				f$image_height = to_count(parts[2]);
				
				
			print fmt("%s -- %s", parts[1], parts[2]);
			### Release the delay ticket.
			#--exiftool_file_map[desc$source]$log_delay_tickets;
			##print fmt("log delay tickets: %d", exiftool_file_map[desc$source]$log_delay_tickets);
			}
		}
		
	}

event FileAnalysis::linear_data(f: Info, data: string)
	{
	if ( f$running_exiftool )
		{
		if ( ! f?$exiftool_data_fifo )
			{
			f$exiftool_data_fifo = open(fmt("%s.exiftool_fifo", f$fid));
			enable_raw_output(f$exiftool_data_fifo);
			}
		#print "sending crap";
		#print f$exiftool_data_fifo, data;
		#write_file(f$exiftool_data_fifo, data);
		write_file(f$exiftool_data_fifo, bytestring_to_hexstr(data));
		}
	}
	
event FileAnalysis::linear_data_done(f: Info)
	{
	if ( f?$exiftool_data_fifo )
		{
		#print fmt("exiftool_hash::%s linear data done", f$fid);
		close(f$exiftool_data_fifo);
		}
	}
	
event FileAnalysis::trigger(f: Info, trig: Trigger)
	{
	if ( trig == IDENTIFIED_MIME && ACTION_EXIFTOOL in f$actions && ! f$running_exiftool )
		{
		#++f$log_delay_tickets;
		
		f$running_exiftool=T;
		#print fmt("creating %s.exiftool_fifo", f$fid);
		system(fmt("rm -f %s.exiftool_fifo; mkfifo %s.exiftool_fifo", f$fid, f$fid));
		
		local name = fmt("exiftool_hash::%s", f$fid);
		exiftool_file_map[name] = f;
		
		#print fmt("%s trying it", name);
		Input::add_event([$name=name,
		                  $source=fmt("cat %s.exiftool_fifo | perl -pe 's/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg' | exiftool -G -j - |", f$fid),
		                  #$source=fmt("cat %s.exiftool_fifo | exiftool -j - |", f$fid),
		                  $fields=exiftoolVal, $ev=exiftool_line,
		                  $mode=Input::STREAM, $reader=Input::READER_RAW]);
		}
	}
