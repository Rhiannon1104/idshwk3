global agent:table[addr] of table[string] of int;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
		local ipaddr : addr = c$id$orig_h;
		local ua : string = to_lower(c$http$user_agent);
		if(ipaddr !in agent)
		{
			agent[ipaddr][ua]=1;
		}
		else if(ua !in agent[ipaddr])
		{
			agent[ipaddr][ua]=1;
		}
		else
		{
			agent[ipaddr][ua]+=1;
			if(agent[ipaddr][ua]==3)
			{
				print fmt("%s is a proxy",ipaddr);
			}
		}
	}
