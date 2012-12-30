using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Data;
using System.Text.RegularExpressions;
using System.Threading;

namespace Org.Reddragonit.Net.DHCP
{
    public class Server
    {

        private static readonly Regex _regHex = new Regex("^0x([0-9a-fA-F][0-9a-fA-F])+$", RegexOptions.Compiled | RegexOptions.ECMAScript);

        public static Server StartServer(IPAddress addy, int inport, int outport, delGetIP getIP, delGetOptions getOptions, delProcessRenew processRenew, delReleaseIP releaseIP, delLogLine log)
        {
            return new Server(addy, inport, outport,getIP,getOptions,processRenew,releaseIP,log);
		}

        private int _inport;
        private int _outport;
        private IPAddress _serverIP;
        private UdpClient _in;
        private UdpClient _out;
        private IPEndPoint _outPoint;
        private bool _done;
        public bool Done
        {
            get { return _done; }
        }

        private delLogLine _log;
        private delGetIP _getIP;
        private delGetOptions _getOptions;
        private delProcessRenew _processRenew;
        private delReleaseIP _releaseIP;

        private Server(IPAddress addy, int inport, int outport,delGetIP getIP,delGetOptions getOptions,delProcessRenew processRenew,delReleaseIP releaseIP, delLogLine log)
        {
            _serverIP = addy;
            _inport = inport;
            _outport = outport;
            _getIP = getIP;
            _getOptions = getOptions;
            _processRenew = processRenew;
            _releaseIP = releaseIP;
            _log = log;
        }

        private void Log(LogLevels level,string line)
        {
            if (_log != null)
                _log(level,line);
        }

        private void Log(Exception e)
        {
            Log(LogLevels.Error, e.Message);
            Log(LogLevels.Error, e.StackTrace);
            if (e.InnerException != null)
                Log(e.InnerException);
        }

        public void Start()
        {
            _done = false;
            Log(LogLevels.Debug,"Binding incoming client for DHCP to broadcast listening on port " + _inport.ToString());
            _in = new UdpClient(new IPEndPoint(_serverIP, _inport));
            _out = new UdpClient(new IPEndPoint(_serverIP, _outport));
            _out.DontFragment = true;
            _out.EnableBroadcast = true;
            _outPoint = new IPEndPoint(IPAddress.Broadcast, _outport);
            _in.BeginReceive(new AsyncCallback(ReceiveCallback), null);
        }

        private void Stop()
        {
            _done = true;
            try
            {
                _in.Close();
            }
            catch (Exception e) {
                Log(e);
            }
        }

        private void ReceiveCallback(IAsyncResult ar)
        {
            if (!_done)
            {
                try
                {
                    IPEndPoint endpoint = null;
                    byte[] data = _in.EndReceive(ar, ref endpoint);
                    if ((data != null) && (data.Length > 0) && (!_done))
                    {
                        Log(LogLevels.Trace,"DHCP Message recieved, translating...");
                        DHCPMessage msg = new DHCPMessage(data,_log);
                        Log(LogLevels.Trace,"DHCP message received: TYPE: " + msg.Type.ToString()+" FOR MAC: "+BytesToReadableMAC(msg.MAC));
                        string tmp = "DHCP OPTIONS: ";
                        foreach (DHCPOption opt in msg.Options)
                            tmp += opt.Type.ToString() + ": " + System.Text.ASCIIEncoding.ASCII.GetString(opt.Value) + "\n";
                        Log(LogLevels.Trace,tmp);
                        tmp = "REQUESTED OPTIONS: ";
                        foreach (DHCPOptionEnum otype in msg.RequestedOptions)
                            tmp += otype.ToString() + ", ";
                        Log(LogLevels.Trace,tmp);
                        DateTime start = DateTime.Now;
                        ProcessMessage(msg);
                        Log(LogLevels.Trace,"Time to process DHCP message: " + DateTime.Now.Subtract(start).TotalMilliseconds.ToString() + "ms");
                        if (!_done)
                        {
                            Log(LogLevels.Trace,"Message received for DHCP Server restarting async recieve to obtain next message.");
                            _in.BeginReceive(new AsyncCallback(ReceiveCallback), null);
                        }
                    }
                }
                catch (Exception err)
                {
                	Log(LogLevels.Trace,"An error occured processing the message, restarting receive...");
                    Log(err);
                    if (!_done)
                    {
                        Log(LogLevels.Trace,"Message received for DHCP Server restarting async recieve to obtain next message.");
                        _in.BeginReceive(new AsyncCallback(ReceiveCallback), null);
                    }
                }
            }
        }

        #region Message Handling
        private void ProcessMessage(DHCPMessage msg)
        {
            if (msg.OpCode == DHCPOpCode.BOOTREQUEST)
            {
                switch (msg.Type)
                {
                    case DHCPMsgType.DHCPDISCOVER:
                    case DHCPMsgType.DHCPREQUEST:
                        ProcessRequest(msg);
                        break;
                    case DHCPMsgType.DHCPDECLINE:
                    case DHCPMsgType.DHCPRELEASE:
                        ProcessDecline(msg);
                        break;
                    case DHCPMsgType.DHCPINFORM:
                        ProcessInform(msg);
                        break;
                }
            }
        }

        private static long IPToLong(IPAddress address)
        {
            MemoryStream ms = new MemoryStream();
            ms.Write(address.GetAddressBytes(), 0, address.GetAddressBytes().Length);
            while (ms.Length < 8)
                ms.WriteByte(0);
            return System.BitConverter.ToInt64(ms.ToArray(), 0);
        }

        private void ProcessInform(DHCPMessage msg)
        {
            if (msg[DHCPOptionEnum.ServerIdentifier] == null)
                return;
            else if (new IPAddress(msg[DHCPOptionEnum.ServerIdentifier]).ToString() != _serverIP.ToString())
                return;
            string mac = BytesToReadableMAC(msg.MAC);
            IPAddress ip = _getIP(mac.Replace(":", ""));
            Dictionary<DHCPOptionEnum, object> options = _getOptions(mac.Replace(":", ""));
            msg.Type = DHCPMsgType.DHCPACK;
            msg.OpCode = DHCPOpCode.BOOTREPLY;
            msg = SetDHCPOptions(msg, ip, options);
            msg.Seconds = (short)DateTime.Now.Subtract(msg.Start).TotalSeconds;
            byte[] bmsg = msg.Bytes;
            _out.Send(bmsg, bmsg.Length, _outPoint);
            return;
        }

        private void ProcessDecline(DHCPMessage msg)
        {
            _releaseIP(BytesToReadableMAC(msg.MAC).Replace(":", ""),msg.AssignedIP);
        }

        private void ProcessRequest(DHCPMessage msg)
        {
            if (msg[DHCPOptionEnum.ServerIdentifier] != null)
            {
                if (new IPAddress(msg[DHCPOptionEnum.ServerIdentifier]).ToString() != _serverIP.ToString())
                    return;
            }
            string mac = BytesToReadableMAC(msg.MAC);
            IPAddress ip = _getIP(mac.Replace(":", ""));
            Dictionary<DHCPOptionEnum, object> options = _getOptions(mac.Replace(":", ""));
            msg.Type = DHCPMsgType.DHCPACK;
            msg.OpCode = DHCPOpCode.BOOTREPLY;
            msg = SetDHCPOptions(msg, ip, options);
            msg.Seconds = (short)DateTime.Now.Subtract(msg.Start).TotalSeconds;
            byte[] bmsg = msg.Bytes;
            _out.Send(bmsg, bmsg.Length, _outPoint);
            return;
        }

        private DHCPMessage SetDHCPOptions(DHCPMessage msg, IPAddress ip,Dictionary<DHCPOptionEnum,object> options)
        {
            if (!options.ContainsKey(DHCPOptionEnum.IPAddressLeaseTime))
                options.Add(DHCPOptionEnum.IPAddressLeaseTime,(3600*24));
            if (options.ContainsKey(DHCPOptionEnum.ServerIdentifier))
                options.Remove(DHCPOptionEnum.ServerIdentifier);
            options.Add(DHCPOptionEnum.ServerIdentifier, _serverIP);
            msg.AssignedIP = ip;
            msg.ServerIP = _serverIP;
            foreach (DHCPOptionEnum opt in options.Keys)
            {
                Log(LogLevels.Trace, "Setting option " + opt.ToString() + " for request");
                msg[opt] = null;
                if (options[opt] is byte[])
                    msg[opt] = (byte[])options[opt];
                else if (options[opt] is List<byte>)
                    msg[opt] = ((List<byte>)options[opt]).ToArray();
                else if (options[opt] is MemoryStream)
                    msg[opt] = ((MemoryStream)options[opt]).ToArray();
                else if (_regHex.IsMatch(options[opt].ToString()))
                    msg[opt] = HexStringToByte(options[opt].ToString());
                else
                {
                    switch (opt)
                    {
                        case DHCPOptionEnum.DomainNameServer:
                        case DHCPOptionEnum.NetworkInformationServers:
                        case DHCPOptionEnum.NetworkTimeProtocolServers:
                        case DHCPOptionEnum.NetBIOSoverTCPIPNameServer:
                        case DHCPOptionEnum.NetBIOSoverTCPIPDatagramDistributionServer:
                        case DHCPOptionEnum.XWindowSystemDisplayManager:
                        case DHCPOptionEnum.XWindowSystemFontServer:
                        case DHCPOptionEnum.NetworkInformationServicePlusServers:
                        case DHCPOptionEnum.SMTPServer:
                        case DHCPOptionEnum.NNTPServer:
                        case DHCPOptionEnum.DefaultWWWServer:
                        case DHCPOptionEnum.DefaultFingerServer:
                        case DHCPOptionEnum.DefaultIRCServer:
                        case DHCPOptionEnum.StreetTalkServer:
                        case DHCPOptionEnum.STDAServer:
                        case DHCPOptionEnum.BCMCSControllerIPv4AddressList:
                            List<byte> tips = new List<byte>();
                            if (options[opt] is IPAddress)
                                msg[opt] = ((IPAddress)options[opt]).GetAddressBytes();
                            else if (options[opt] is string)
                            {
                                if (((string)options[opt]).Contains(","))
                                {
                                    foreach (string str in ((string)options[opt]).Split(','))
                                        tips.AddRange(IPAddress.Parse(str).GetAddressBytes());
                                    msg[opt] = tips.ToArray();
                                }
                                else if (((string)options[opt]).Contains(" "))
                                {
                                    foreach (string str in ((string)options[opt]).Split(' '))
                                        tips.AddRange(IPAddress.Parse(str).GetAddressBytes());
                                    msg[opt] = tips.ToArray();
                                }
                                else
                                    msg[opt] = IPAddress.Parse((string)options[opt]).GetAddressBytes();
                            }
                            else if (options[opt] is IPAddress[] || options[opt] is List<IPAddress>)
                            {
                                foreach (IPAddress dip in (options[opt] is IPAddress[] ? (IPAddress[])options[opt] : ((List<IPAddress>)options[opt]).ToArray()))
                                    tips.AddRange(dip.GetAddressBytes());
                                msg[opt] = tips.ToArray();
                            }
                            else if (options[opt] is string[] || options[opt] is List<string>)
                            {
                                foreach (string str in (options[opt] is string[] ? (string[])options[opt] : ((List<string>)options[opt]).ToArray()))
                                    tips.AddRange(IPAddress.Parse(str).GetAddressBytes());
                                msg[opt] = tips.ToArray();
                            }
                            break;
                        case DHCPOptionEnum.PolicyFilter:
                            List<byte> tpfs = new List<byte>();
                            if (options[opt] is string)
                            {
                                string spf = (string)options[opt];
                                if (spf.Contains(","))
                                {
                                    foreach (string str in spf.Split(','))
                                    {
                                        if (str.Length > 0)
                                        {
                                            tpfs.AddRange(IPAddress.Parse(str.Substring(0, str.IndexOf("/"))).GetAddressBytes());
                                            tpfs.AddRange(IPAddress.Parse(str.Substring(str.IndexOf("/") + 1)).GetAddressBytes());
                                        }
                                    }
                                }
                                else if (spf.Contains(" "))
                                {
                                    foreach (string str in spf.Split(' '))
                                    {
                                        if (str.Length > 0)
                                        {
                                            tpfs.AddRange(IPAddress.Parse(str.Substring(0, str.IndexOf("/"))).GetAddressBytes());
                                            tpfs.AddRange(IPAddress.Parse(str.Substring(str.IndexOf("/") + 1)).GetAddressBytes());
                                        }
                                    }
                                }
                                msg[opt] = (tpfs.Count > 0 ? tpfs.ToArray() : null);
                            }
                            break;
                        case DHCPOptionEnum.StaticRoute:
                            List<byte> tsrs = new List<byte>();
                            if (options[opt] is string)
                            {
                                string srs = (string)options[opt];
                                if (srs.Contains(","))
                                {
                                    foreach (string str in srs.Split(','))
                                    {
                                        if (str.Length > 0)
                                        {
                                            tsrs.AddRange(IPAddress.Parse(str.Substring(0, str.IndexOf("-"))).GetAddressBytes());
                                            tsrs.AddRange(IPAddress.Parse(str.Substring(str.IndexOf("-") + 1)).GetAddressBytes());
                                        }
                                    }
                                }
                                else if (srs.Contains(" "))
                                {
                                    foreach (string str in srs.Split(' '))
                                    {
                                        if (str.Length > 0)
                                        {
                                            tsrs.AddRange(IPAddress.Parse(str.Substring(0, str.IndexOf("-"))).GetAddressBytes());
                                            tsrs.AddRange(IPAddress.Parse(str.Substring(str.IndexOf("-") + 1)).GetAddressBytes());
                                        }
                                    }
                                }
                                msg[opt] = (tsrs.Count > 0 ? tsrs.ToArray() : null);
                            }
                            break;
                        case DHCPOptionEnum.AllSubnetsAreLocal:
                        case DHCPOptionEnum.IpForwarding:
                        case DHCPOptionEnum.NonLocalSourceRouting:
                        case DHCPOptionEnum.PerformMaskDiscovery:
                        case DHCPOptionEnum.MaskSupplier:
                        case DHCPOptionEnum.PerformRouterDiscovery:
                        case DHCPOptionEnum.TrailerEncapsulation:
                        case DHCPOptionEnum.EthernetEncapsulation:
                        case DHCPOptionEnum.TCPKeepaliveGarbage:
                        case DHCPOptionEnum.OptionOverload:
                        case DHCPOptionEnum.AutoConfigure:
                            if (options[opt] is bool)
                                msg[opt] = new byte[] { (byte)((bool)options[opt] ? 1 : 0) };
                            else if (options[opt] is string)
                                msg[opt] = new byte[] { (byte)(bool.Parse((string)options[opt]) ? 1 : 0) };
                            break;
                        case DHCPOptionEnum.DefaultIPTimeToLive:
                        case DHCPOptionEnum.TCPDefaultTTL:
                        case DHCPOptionEnum.NetBIOSoverTCPIPNodeType:
                        case DHCPOptionEnum.DHCPMessageTYPE:
                            if (options[opt] is byte)
                                msg[opt] = new byte[] { (byte)options[opt] };
                            else if (options[opt] is string)
                                msg[opt] = new byte[] { byte.Parse((string)options[opt]) };
                            else if (options[opt] is int || options[opt] is Int32 || options[opt] is Int16 || options[opt] is Int16 || options[opt] is Int64 || options[opt] is long || options[opt] is double || options[opt] is Double || options[opt] is decimal || options[opt] is Decimal || options[opt] is uint || options[opt] is UInt16 || options[opt] is UInt32 || options[opt] is UInt64 || options[opt] is ushort || options[opt] is ulong || options[opt] is float)
                                msg[opt] = new byte[] { byte.Parse(options[opt].ToString()) };
                            break;
                        case DHCPOptionEnum.AssociatedIP:
                        case DHCPOptionEnum.RequestedIPAddress:
                        case DHCPOptionEnum.SubnetMask:
                        case DHCPOptionEnum.Router:
                        case DHCPOptionEnum.TimeServer:
                        case DHCPOptionEnum.NameServer:
                        case DHCPOptionEnum.LogServer:
                        case DHCPOptionEnum.CookieServer:
                        case DHCPOptionEnum.LPRServer:
                        case DHCPOptionEnum.ImpressServer:
                        case DHCPOptionEnum.ResourceLocServer:
                        case DHCPOptionEnum.SwapServer:
                        case DHCPOptionEnum.BroadcastAddress:
                        case DHCPOptionEnum.RouterSolicitationAddress:
                        case DHCPOptionEnum.ServerIdentifier:
                        case DHCPOptionEnum.SubnetSelection:
                            if (options[opt] is string)
                                msg[opt] = IPAddress.Parse((string)options[opt]).GetAddressBytes();
                            else if (options[opt] is IPAddress)
                                msg[opt] = ((IPAddress)options[opt]).GetAddressBytes();
                            break;
                        case DHCPOptionEnum.TimeOffset:
                            if (options[opt] is string)
                                msg[opt] = BitConverter.GetBytes(int.Parse((string)options[opt]));
                            else if (options[opt] is int || options[opt] is Int32 || options[opt] is Int16 || options[opt] is Int16 || options[opt] is Int64 || options[opt] is long || options[opt] is double || options[opt] is Double || options[opt] is decimal || options[opt] is Decimal || options[opt] is uint || options[opt] is UInt16 || options[opt] is UInt32 || options[opt] is UInt64 || options[opt] is ushort || options[opt] is ulong || options[opt] is float)
                                msg[opt] = BitConverter.GetBytes(int.Parse(options[opt].ToString()));
                            break;
                        case DHCPOptionEnum.PathMTUAgingTimeout:
                        case DHCPOptionEnum.ARPCacheTimeout:
                        case DHCPOptionEnum.TCPKeepaliveInterval:
                        case DHCPOptionEnum.IPAddressLeaseTime:
                        case DHCPOptionEnum.RenewalTimeValue_T1:
                        case DHCPOptionEnum.RebindingTimeValue_T2:
                        case DHCPOptionEnum.ClientLastTransactionTime:
                            if (options[opt] is string)
                                msg[opt] = BitConverter.GetBytes(uint.Parse((string)options[opt]));
                            else if (options[opt] is int || options[opt] is Int32 || options[opt] is Int16 || options[opt] is Int16 || options[opt] is Int64 || options[opt] is long || options[opt] is double || options[opt] is Double || options[opt] is decimal || options[opt] is Decimal || options[opt] is uint || options[opt] is UInt16 || options[opt] is UInt32 || options[opt] is UInt64 || options[opt] is ushort || options[opt] is ulong || options[opt] is float)
                                msg[opt] = BitConverter.GetBytes(uint.Parse(options[opt].ToString()));
                            break;
                        case DHCPOptionEnum.BootFileSize:
                        case DHCPOptionEnum.MaximumDatagramReAssemblySize:
                        case DHCPOptionEnum.InterfaceMTU:
                        case DHCPOptionEnum.MaximumDHCPMessageSize:
                            if (options[opt] is string)
                                msg[opt] = BitConverter.GetBytes(ushort.Parse((string)options[opt]));
                            else if (options[opt] is int || options[opt] is Int32 || options[opt] is Int16 || options[opt] is Int16 || options[opt] is Int64 || options[opt] is long || options[opt] is double || options[opt] is Double || options[opt] is decimal || options[opt] is Decimal || options[opt] is uint || options[opt] is UInt16 || options[opt] is UInt32 || options[opt] is UInt64 || options[opt] is ushort || options[opt] is ulong || options[opt] is float)
                                msg[opt] = BitConverter.GetBytes(ushort.Parse(options[opt].ToString()));
                            break;
                        case DHCPOptionEnum.PathMTUPlateauTable:
                            List<byte> tmtu = new List<byte>();
                            if (options[opt] is string)
                            {
                                string smtu = (string)options[opt];
                                if (smtu.Contains(","))
                                {
                                    foreach (string str in smtu.Split(','))
                                    {
                                        if (str.Length > 0)
                                            tmtu.AddRange(BitConverter.GetBytes(ushort.Parse(str)));
                                    }
                                }
                                else if (smtu.Contains(" "))
                                {
                                    foreach (string str in smtu.Split(' '))
                                    {
                                        if (str.Length > 0)
                                            tmtu.AddRange(BitConverter.GetBytes(ushort.Parse(str)));
                                    }
                                }
                            }
                            else if (options[opt] is ushort[] || options[opt] is List<ushort>)
                            {
                                foreach (ushort us in (options[opt] is ushort[] ? (ushort[])options[opt] : ((List<ushort>)options[opt]).ToArray()))
                                    tmtu.AddRange(BitConverter.GetBytes(us));
                            }
                            msg[opt] = (tmtu.Count > 0 ? tmtu.ToArray() : null);
                            break;
                        default:
                            if (options[opt] is string)
                                msg[opt] = ASCIIEncoding.ASCII.GetBytes((string)options[opt]);
                            break;
                    }
                    if (msg[opt] == null)
                        throw new Exception("Unable to convert object " + options[opt].GetType().FullName + " for option " + opt.ToString());
                    else
                        Log(LogLevels.Trace, "Set option " + opt.ToString() + " for request");
                }
            }
            msg[DHCPOptionEnum.ParameterRequestList] = null;
            return msg;
        }

        private byte[] HexStringToByte(string val)
        {
            val = val.Substring(2).ToUpper();
            byte[] ret = new byte[val.Length / 2];
            for (int x = 0; x < val.Length; x += 2)
            {
                ret[x/2] = (byte)Int32.Parse(val.Substring(x * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return ret;
        }

        internal static string ByteArrayToHexString(byte[] val)
        {
            return "0x"+BitConverter.ToString(val).Replace("-", string.Empty);
        }
        #endregion

        private string BytesToReadableMAC(byte[] p)
        {
            char[] c = new char[p.Length * 3 -1];

            byte b;

            for (int y = 0; y < p.Length; y++)
            {

                b = ((byte)(p[y] >> 4));

                c[(y*3)] = (char)(b > 9 ? b + 0x37 : b + 0x30);

                b = ((byte)(p[y] & 0xF));

                c[(y*3)+1] = (char)(b > 9 ? b + 0x37 : b + 0x30);

                if ((y * 3) + 2<c.Length)
                    c[(y * 3) + 2] = ':';
            }

            return new string(c);
        }
    }
}
