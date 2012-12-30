using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace Org.Reddragonit.Net.DHCP
{
    public delegate void delLogLine(LogLevels level,string line);
    public delegate Dictionary<DHCPOptionEnum,object> delGetOptions(string mac);
    public delegate IPAddress delGetIP(string mac);
    public delegate void delReleaseIP(string mac,IPAddress ip);
    public delegate Dictionary<DHCPOptionEnum, object> delProcessRenew(string mac, ref IPAddress ip);
}
