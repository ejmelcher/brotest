module FileAnalysis;

export {
	redef enum Action += { ACTION_HASH_MD5 };
	redef enum Trigger  += { IDENTIFIED_MD5 };
	
	redef record Info += {
		md5:    string &log &optional;
		
		calc_md5: bool &default=F;
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
	}

event FileAnalysis::linear_data_done(f: Info) &priority=5
	{
	if ( f$calc_md5 )
		{
		f$md5 = md5_hash_finish(f$fid);
		event FileAnalysis::trigger(f, IDENTIFIED_MD5);
		}
	}