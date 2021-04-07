global relation:table[addr] of set[string];
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if(is_orig)
	{
	        if(name == "User-Agent")
		{
		        if(!(to_lower(value) in relation[c$id$orig_h]))
			{
			    add relation[c$id$orig_h][to_lower(value)];					
			}						
		}					
	}	
}

event zeek_done()
{
	for(src_ip in relation)
	{
		if(|relation[src_ip]|>=3)
		{
			 print fmt("%s is a proxy", src_ip);
		}
	}
}
