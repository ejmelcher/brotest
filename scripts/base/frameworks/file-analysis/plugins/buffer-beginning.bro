##! This plugin makes it possible for a user to request a certain number 
##! of bytes of the beginning of individual files to be reconstructed and buffered
##! by the file analysis framework.  It provides the data as a single string
##! and dechunked to allow "whole" string matching with a pattern.

module FileAnalysis;

export {
	redef enum Action += { ACTION_BUFFER_BEGINNING };
	redef enum Trigger  += { BEGINNING_BUFFERED };
	
	redef record Info += {
		## The minimum number of bytes of the beginning of a file 
		## that should be buffered for inspection.
		buffer_beginning_bytes: count &default=0;
		
		## The bytes of this file that are buffered.
		buffer_beginning:    string  &optional;
	};
}

event FileAnalysis::linear_data(f: Info, data: string) &priority=5
	{
	if ( ACTION_BUFFER_BEGINNING in f$actions && 
	     (! f?$buffer_beginning || |f$buffer_beginning| < f$buffer_beginning_bytes))
		{
		if ( ! f?$buffer_beginning )
			f$buffer_beginning = data;
		else
			f$buffer_beginning = f$buffer_beginning + data;
		
		if ( |f$buffer_beginning| >= f$buffer_beginning_bytes )
			{
			event FileAnalysis::trigger(f, BEGINNING_BUFFERED);
			}
		}
	}
