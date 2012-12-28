using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace Org.Reddragonit.Net.DHCP
{
    internal class Utility
    {
        public static List<IPAddress> GetIPsInRange(IPAddress start, IPAddress end)
        {
            List<IPAddress> ret = new List<IPAddress>();
            ret.Add(start);
            if (start.ToString() != end.ToString())
            {
                byte[] tmp = start.GetAddressBytes();
                IncrementByteArray(ref tmp, tmp.Length - 1);
                while (new IPAddress(tmp).ToString() != end.ToString())
                {
                    ret.Add(new IPAddress(tmp));
                    IncrementByteArray(ref tmp, tmp.Length - 1);
                }
                ret.Add(end);
            }
            return ret;
        }

        private static void IncrementByteArray(ref byte[] val, int curIndex)
        {
            if (curIndex >= val.Length)
                throw new Exception("Unable to increment byte array past 0 index, number over flow");
            if ((int)val[curIndex] + 1 > 255)
            {
                for (int x = curIndex; x < val.Length; x++)
                {
                    val[x] = 0;
                }
                IncrementByteArray(ref val, curIndex - 1);
            }
            else
                val[curIndex]++;
        }

        public static string FormatMAC(string mac)
        {
            mac = mac.Replace("-", ":");
            if (!mac.Contains(":"))
            {
                string ret = "";
                for (int x = 0; x < mac.Length; x += 2)
                {
                    ret += ":" + mac[x].ToString() + mac[x + 1].ToString();
                }
                return ret.Substring(1);
            }
            return mac;
        }

    }
}
