module FileAnalysis;

export {
	redef enum Action += { ACTION_EXTRACT };
	redef enum Trigger  += { EXTRACTED };
	
	redef record Info += {
		## Name of the file on disk where this file was extracted.
		disk_file:    file &log &optional;
	};
}

global the_file = 0;

event FileAnalysis::linear_data(f: Info, data: string) &priority=5
	{
	if ( ACTION_EXTRACT in f$actions )
		{
		if ( ! f?$disk_file )
			{
			f$disk_file = open(fmt("extract-plugin-file-%d", ++the_file));
			enable_raw_output(f$disk_file);
			}
		
		print f$disk_file, data;
		}
	}
	
event FileAnalysis::linear_data_done(f: Info) &priority=5
	{
	if ( f?$disk_file )
		{
		close(f$disk_file);
		event FileAnalysis::trigger(f, EXTRACTED);
		}
	}
