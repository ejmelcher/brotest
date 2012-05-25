module FileAnalysis;

export {
	redef enum Action += { 
		ACTION_HASH_MD5, 
		ACTION_HASH_SHA1,
		ACTION_HASH_SHA256
	};
	
	redef enum Trigger  += { 
		IDENTIFIED_MD5,
		IDENTIFIED_SHA1,
		IDENTIFIED_SHA256
	};
	
	redef record Info += {
		md5:     string &log &optional;
		sha1:    string &log &optional;
		sha256:  string &log &optional;
		
		calc_md5:    bool &default=F;
		calc_sha1:   bool &default=F;
		calc_sha256: bool &default=F;
		
	};
}

event FileAnalysis::linear_data(f: Info, data: string) &priority=5
	{
	if ( ACTION_HASH_MD5 in f$actions )
		{
		if ( ! f$calc_md5 )
			{
			f$calc_md5 = T;
			md5_hash_init(f$fid);
			}
		md5_hash_update(f$fid, data);
		}
		
	if ( ACTION_HASH_SHA1 in f$actions )
		{
		if ( ! f$calc_sha1 )
			{
			f$calc_sha1 = T;
			sha1_hash_init(f$fid);
			}
		sha1_hash_update(f$fid, data);
		}
	
	if ( ACTION_HASH_SHA256 in f$actions )
		{
		if ( ! f$calc_sha256 )
			{
			f$calc_sha256 = T;
			sha256_hash_init(f$fid);
			}
		sha256_hash_update(f$fid, data);
		}
	}

event FileAnalysis::linear_data_done(f: Info) &priority=5
	{
	if ( f$calc_md5 )
		{
		f$md5 = md5_hash_finish(f$fid);
		event FileAnalysis::trigger(f, IDENTIFIED_MD5);
		}
		
	if ( f$calc_sha1 )
		{
		f$sha1 = sha1_hash_finish(f$fid);
		event FileAnalysis::trigger(f, IDENTIFIED_SHA1);
		}
	if ( f$calc_sha256 )
		{
		f$sha256 = sha256_hash_finish(f$fid);
		event FileAnalysis::trigger(f, IDENTIFIED_SHA256);
		}
	}