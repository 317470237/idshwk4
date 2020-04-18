global t: table[addr] of record{
    count_all: double;
    count_404: double;
    count_404_uni: double;
    url: set[string];
};
global oritime: time;
global iinterval: interval;

function output()
{
	for(a in t)
	{
		if(t[a]$count_all>2)
		{
			if((t[a]$count_404/t[a]$count_all)>0.2)
			{
				if((t[a]$count_404_uni/t[a]$count_404)>0.5)
				{
					print fmt("%s is the orig_h, %d is the count of 404 response , %d is the unique count of url response 404", a, t[a]$count_404, t[a]$count_404_uni);
				}
			}
		}
	}
}

event zeek_init()
{
	oritime = current_time();
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	iinterval = current_time() - oritime;
	if(iinterval >= 10min)
	{
		oritime = current_time();
		output();
		t = table();
	}
	
	if ( c$id$orig_h !in t )
	{
		t[c$id$orig_h] = record($count_all=1, $count_404=0, $count_404_uni=0, $url=set(""));
	}
	else
	{
		t[c$id$orig_h]$count_all += 1;
	}

	if(code == 404)
	{
		t[c$id$orig_h]$count_404 += 1;
		if(HTTP::build_url_http(c$http) !in t[c$id$orig_h]$url)
		{
			add t[c$id$orig_h]$url[HTTP::build_url_http(c$http)];
			t[c$id$orig_h]$count_404_uni += 1;
		}
	}
}

event zeek_done()
{
	output();
}
