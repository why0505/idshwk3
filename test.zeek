global IPTable :table[addr] of set[string] ;
global ip:addr;

event http_header(c: connection, is_orig: bool, name: string, value: string)
{ 
  ip = c$id$orig_h;
  if(c$http?$user_agent)
  {
    local agents: string = to_lower(c$http$user_agent);
    if(ip in IPTable)
    {
      add IPTable[ip][agents];
    }
    else
    {
      IPTable[ip]=set(agents);
    }
  }
}

event zeek_done() 
{
  for(i in IPTable)
  {
    if(|IPTable[i]|>=3)
    {
      print fmt("%s is a proxy",i);
    }
  }  
}
