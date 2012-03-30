##! This plugin makes it possible for a user to request a certain number 
##! of bytes of the beginning of individual files to be reconstructed and buffered
##! by the file analysis framework.  It provides the data as a single string
##! and dechunked to allow "whole" string matching with a pattern.

module FileAnalysis;

export {
	redef enum Action += { ACTION_BUFFER_BEGINNING };
	redef enum Trigger  += { BEGINNING_BUFFERED };
	
	redef record Info += {
		## The number of bytes of the beginning of a file that should
		## be buffered for inspection.
		buffer_beginning_bytes: count &optional;
		
		## The bytes of this 
		buffer_beginning:    string  &optional;
	};
}

event FileAnalysis::linear_data(f: Info, data: string) &priority=5
	{
	if ( ACTION_BUFFER_BEGINNING in f$actions )
		{
		if ( )
		}
	}
