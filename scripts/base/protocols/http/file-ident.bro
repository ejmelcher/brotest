##! Identification of file types in HTTP response bodies with file content sniffing.

@load base/frameworks/file-analysis
@load base/frameworks/signatures
@load base/frameworks/notice
@load ./main
@load ./utils

# Add the magic number signatures to the core signature set.
redef signature_files += "base/protocols/http/file-ident.sig";
# Ignore the signatures used to match files
redef Signatures::ignored_ids += /^matchfile-/;

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates when the file extension doesn't seem to match the file contents.
		Incorrect_File_Type,
	};

	redef record Info += {
		
		## Identifier used by the file analysis framework.
		fid:          string   &optional;
		
		## Mime type of response body identified by content sniffing.
		mime_type:    string   &log &optional;
		
		## Indicates that no data of the current file transfer has been
		## seen yet.  After the first :bro:id:`http_entity_data` event, it 
		## will be set to F.
		first_chunk:     bool &default=T;
		
		bytes: count &default=0;
	};
	
	## Mapping between mime types and regular expressions for URLs
	## The :bro:enum:`HTTP::Incorrect_File_Type` notice is generated if the pattern 
	## doesn't match the mime type that was discovered.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
	
	## A pattern for filtering out :bro:enum:`HTTP::Incorrect_File_Type` urls
	## that are not noteworthy before a notice is created.  Each
	## pattern added should match the complete URL (the matched URLs include
	## "http://" at the beginning).
	const ignored_incorrect_file_type_urls = /^$/ &redef;
}

event signature_match(state: signature_state, msg: string, data: string) &priority=5
	{
	# Only signatures matching file types are dealt with here.
	if ( /^matchfile-/ !in state$sig_id ) return;

	local c = state$conn;
	set_state(c, F, F);
	
	# Not much point in any of this if we don't know about the HTTP session.
	if ( ! c?$http ) return;
	
	# Set the mime type that was detected.
	c$http$mime_type = msg;
	
	if ( msg in mime_types_extensions && 
	     c$http?$uri && mime_types_extensions[msg] !in c$http$uri )
		{
		local url = build_url_http(c$http);
		
		if ( url == ignored_incorrect_file_type_urls )
			return;
		
		local message = fmt("%s %s %s", msg, c$http$method, url);
		NOTICE([$note=Incorrect_File_Type,
		        $msg=message,
		        $conn=c,
		        $method=c$http$method,
		        $URL=url]);
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=5
	{
	# The file id needs to be the URL with the originator ip address if this is a partial content 
	# response.
	if ( ! c$http?$fid )
		c$http$fid = c$http$range_request ? cat(c$id$orig_h,build_url(c$http)) : cat(c$uid,c$http$trans_depth);
	local offset = c$http$data_offset + c$http$bytes;

	FileAnalysis::send_data(c$http$fid, offset, data);
	FileAnalysis::send_conn(c$http$fid, c);
	c$http$bytes += |data|;
	
	if ( c$http$first_chunk && ! c$http?$mime_type )
		c$http$mime_type = split1(identify_data(data, T), /;/)[1];
	}
	
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
	{
	if ( ! c$http$range_request )
		FileAnalysis::send_EOF(cat(c$uid,c$http$trans_depth));
	
	delete c$http$bytes;
	delete c$http$data_offset;
	delete c$http$fid;
	}
	
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-10
	{
	if ( c$http$first_chunk )
		c$http$first_chunk=F;
	}
