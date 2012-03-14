##! Analysis and logging for MIME entities found in SMTP sessions.

@load base/frameworks/file-analysis

@load base/utils/strings
@load base/utils/files
@load ./main

module SMTP;

export {
	redef enum Notice::Type += {
		## Indicates that an MD5 sum was calculated for a MIME message.
		MD5,
	};

	redef enum Log::ID += { ENTITIES_LOG };

	type EntityInfo: record {
		## This is the timestamp of when the MIME content transfer began.
		ts:               time    &log;
		uid:              string  &log;
		id:               conn_id &log;
		## A count to represent the depth of this message transaction in a 
		## single connection where multiple messages were transferred.
		trans_depth:      count  &log;
		## The filename seen in the Content-Disposition header.
		filename:         string  &log &optional;
		## Track how many bytes of the MIME encoded file have been seen.
		content_len:      count   &log &default=0;
		## The mime type of the entity discovered through magic bytes identification.
		mime_type:        string  &log &optional;
		
		## The calculated MD5 sum for the MIME entity.
		md5:              string  &log &optional;
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:         bool    &default=F;
		## This boolean value indicates if an MD5 sum is being calculated 
		## for the current file transfer.
		calculating_md5:  bool    &default=F;
		
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:     bool    &default=F;
		## Store the file handle here for the file currently being extracted.
		extraction_file:  file    &log &optional;
		
		## The file record from the file analysis framework.
		fid:              FileAnalysis::Info &optional;
	};

	redef record Info += {
		## The in-progress entity information.
		current_entity:   EntityInfo &optional;
	};

	redef record State += {
		## Store a count of the number of files that have been transferred in
		## a conversation to create unique file names on disk.
		num_extracted_files:  count   &default=0;
		## Track the number of MIME encoded files transferred during a session.
		mime_level:           count   &default=0;
	};

	## The on-disk prefix for files to be extracted from MIME entity bodies.
	const extraction_prefix = "smtp-entity" &redef;

	global log_mime: event(rec: EntityInfo);
}

event bro_init() &priority=5
	{
	Log::create_stream(SMTP::ENTITIES_LOG, [$columns=EntityInfo, $ev=log_mime]);
	}

function set_session(c: connection, new_entity: bool)
	{
	if ( ! c$smtp?$current_entity || new_entity )
		{
		++c$smtp_state$mime_level;
		
		local info: EntityInfo;
		info$ts=network_time();
		info$uid=c$uid;
		info$id=c$id;
		info$trans_depth=c$smtp$trans_depth;
		info$fid = FileAnalysis::get_file(cat(c$uid, c$smtp$trans_depth, c$smtp_state$mime_level));
		c$smtp$current_entity = info;
		}
	}

event mime_begin_entity(c: connection) &priority=10
	{
	if ( ! c?$smtp ) return;
	
	set_session(c, T);
	FileAnalysis::send_conn(c$smtp$current_entity$fid, c);
	}


## In the event of a content gap during the MIME transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be
## incorrect anyway.
#event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
#	{
#	if ( is_orig || ! c?$smtp || ! c$smtp?$current_entity ) return;
#
#	if ( c$smtp$current_entity$calculating_md5 )
#		{
#		c$smtp$current_entity$calculating_md5 = F;
#		md5_hash_finish(c$id);
#		}
#	}


event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( ! c?$smtp ) return;
	
	if ( h$name == "CONTENT-DISPOSITION" &&
	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$smtp$current_entity$filename = extract_filename_from_content_disposition(h$value);
	}

event mime_end_entity(c: connection) &priority=-5
	{
	if ( ! c?$smtp ) return;

	# This check and the delete below are just to cope with a bug where
	# mime_end_entity can be generated multiple times for the same event.
	if ( ! c$smtp?$current_entity )
		return;

	# Only log if there was some content.
	if ( c$smtp$current_entity$content_len > 0 )
		Log::write(SMTP::ENTITIES_LOG, c$smtp$current_entity);
	
	FileAnalysis::send_EOF(c$smtp$current_entity$fid);
	delete c$smtp$current_entity;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( ! c?$smtp ) return;
	
	local offset = c$smtp$current_entity$content_len;
	FileAnalysis::send_data(c$smtp$current_entity$fid, "SMTP", offset, data);
	c$smtp$current_entity$content_len += |data|;
	}
