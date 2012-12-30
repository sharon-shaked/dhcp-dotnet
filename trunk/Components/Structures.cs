using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Net;

namespace Org.Reddragonit.Net.DHCP.Components
{

    public struct DHCPOption : IComparable
    {
        private DHCPOptionEnum _type;
        public DHCPOptionEnum Type
        {
            get { return _type; }
        }

        public int OptNum
        {
            get { return (int)_type; }
        }

        private byte[] _value;
        internal byte[] Value
        {
            get { return _value; }
            set { _value = value; }
        }

        public string HexValue
        {
            get { return Server.ByteArrayToHexString(_value); }
        }

        internal DHCPOption(byte[] data)
        {
            BinaryReader br = new BinaryReader(new MemoryStream(data));
            _type = (DHCPOptionEnum)br.ReadByte();
            _value = br.ReadBytes((int)br.ReadByte());
        }

        public DHCPOption(DHCPOptionEnum type, byte[] value)
        {
            _type = type;
            _value = value;
        }

        #region IComparable Members

        public int CompareTo(object obj)
        {
            return OptNum.CompareTo(((DHCPOption)obj).OptNum);
        }

        #endregion
    }

    internal struct DHCPMessage
    {
        private DateTime _start;
        public DateTime Start
        {
            get { return _start; }
            set { _start = value; }
        }

        private DHCPOpCode _opcode;
        public DHCPOpCode OpCode
        {
            get { return _opcode; }
            set { _opcode = value; }
        }

        public DHCPMsgType Type{
            get {
                if (this[DHCPOptionEnum.DHCPMessageTYPE] == null)
                    return DHCPMsgType.DHCPDISCOVER;
                return (DHCPMsgType)this[DHCPOptionEnum.DHCPMessageTYPE][0];
            }
            set { 
            this[DHCPOptionEnum.DHCPMessageTYPE] = new byte[] { (byte)value };
            }
        }

        private byte _hardwareType;
        public byte HardwareType
        {
            get { return _hardwareType; }
        }

        private byte _addressLen;
        public byte AddressLen
        {
            get { return _addressLen; }
        }

        private byte _hops;
        public byte Hops
        {
            get { return _hops; }
        }

        private int _transactionID;
        public int TransactionID
        {
            get { return _transactionID; }
        }

        private short _seconds;
        public short Seconds
        {
            get { return _seconds; }
            set { _seconds = value; }
        }

        private bool _broadcast;
        public bool Broadcast
        {
            get { return _broadcast; }
        }

        private int _clientIP;
        public IPAddress ClientIP
        {
            get {
                if (_clientIP == 0)
                    return null;
                return new IPAddress(BitConverter.GetBytes(_clientIP)); }
        }

        private int _assignedIP;
        public IPAddress AssignedIP
        {
            get
            {
                if (_assignedIP == 0)
                    return null;
                return new IPAddress(BitConverter.GetBytes(_assignedIP));
            }
            set
            {
                if (value != null)
                    _assignedIP = BitConverter.ToInt32(value.GetAddressBytes(),0);
                else
                    _assignedIP = 0;
            }
        }

        private int _serverIP;
        public IPAddress ServerIP
        {
            get
            {
                if (_serverIP == 0)
                    return null;
                return new IPAddress(BitConverter.GetBytes(_serverIP));
            }
            set
            {
                if (value != null)
                    _serverIP = BitConverter.ToInt32(value.GetAddressBytes(), 0);
                else
                    _serverIP = 0;
            }
        }

        private int _relayIP;
        public IPAddress RelayIP
        {
            get
            {
                if (_relayIP == 0)
                    return null;
                return new IPAddress(BitConverter.GetBytes(_relayIP));
            }
            set
            {
                if (value != null)
                    _relayIP = BitConverter.ToInt32(value.GetAddressBytes(), 0);
                else
                    _relayIP = 0;
            }
        }

        private byte[] _mac;
        public byte[] MAC
        {
            get { return _mac; }
        }

        private string _serverHostName;
        public string ServerHostName
        {
            get { return _serverHostName; }
            set { _serverHostName = value; }
        }

        private string _file;
        public string File
        {
            get { return _file; }
            set { _file = value; }
        }

        private List<DHCPOption> _options;
        public List<DHCPOption> Options
        {
            get { return _options; }
        }

        public byte[] this[DHCPOptionEnum optype]
        {
            get {
                byte[] ret = null;
                foreach (DHCPOption op in Options)
                {
                    if (op.Type == optype)
                    {
                        ret = op.Value;
                        break;
                    }
                }
                return ret;
            }
            set {
                for (int x = 0; x < Options.Count;x++ )
                {
                    if (Options[x].Type == optype)
                    {
                        _options.RemoveAt(x);
                        break;
                    }
                }
                if (value!=null)
                    _options.Add(new DHCPOption(optype, value));
            }
        }

        public List<DHCPOptionEnum> RequestedOptions
        {
            get
            {
                List<DHCPOptionEnum> ret = new List<DHCPOptionEnum>();
                if (this[DHCPOptionEnum.ParameterRequestList] != null)
                {
                    MemoryStream ms = new MemoryStream(this[DHCPOptionEnum.ParameterRequestList]);
                    while (ms.Position < ms.Length)
                        ret.Add((DHCPOptionEnum)ms.ReadByte());
                }
                return ret;
            }
        }

        public DHCPMessage(byte[] msg,delLogLine log)
        {
            _start = DateTime.Now;
            if (log!=null)
                log(LogLevels.Trace,"Parsing DHCP Message of length: " + msg.Length);
            BinaryReader br = new BinaryReader(new MemoryStream(msg));
            _opcode = (DHCPOpCode)br.ReadByte();
            _hardwareType = br.ReadByte();
            _addressLen = br.ReadByte();
            _hops = br.ReadByte();
            _transactionID = br.ReadInt32();
            _seconds = br.ReadInt16();
            _broadcast = (br.ReadInt16() ^ 0x8000) == 0x8000;
            _clientIP = br.ReadInt32();
            _assignedIP = br.ReadInt32();
            _serverIP = br.ReadInt32();
            _relayIP = br.ReadInt32();
            byte[] tmp = br.ReadBytes(16);
            _mac = new byte[_addressLen];
            for (int x = 0; x < _mac.Length; x++)
                _mac[x] = tmp[x];
            tmp = br.ReadBytes(64);
            MemoryStream ms = new MemoryStream();
            for (int x = 0; x < tmp.Length; x++)
            {
                if (tmp[x] == (byte)'\0')
                    break;
                else
                    ms.WriteByte(tmp[x]);
            }
            _serverHostName = System.Text.ASCIIEncoding.ASCII.GetString(ms.ToArray());
            tmp = br.ReadBytes(128);
            ms = new MemoryStream();
            for (int x = 0; x < tmp.Length; x++)
            {
                if (tmp[x] == (byte)'\0')
                    break;
                else
                    ms.WriteByte(tmp[x]);
            }
            _file = System.Text.ASCIIEncoding.ASCII.GetString(ms.ToArray());
            _options = new List<DHCPOption>();
            if (br.ReadInt32() == BitConverter.ToInt32(new byte[]{(byte)0x63,(byte)0x82,(byte)0x53,(byte)0x63},0))
            {
                byte b;
                while ((b = br.ReadByte()) != (byte)255)
                {
                    tmp = new byte[(int)br.ReadByte()+2];
                    tmp[0] = b;
                    tmp[1] = (byte)(tmp.Length - 2);
                    br.ReadBytes(tmp.Length - 2).CopyTo(tmp, 2);
                    _options.Add(new DHCPOption(tmp));
                }
            }
            
        }

        public byte[] Bytes
        {
            get
            {
                MemoryStream ms = new MemoryStream();
                BinaryWriter bw = new BinaryWriter(ms);
                bw.Write((byte)_opcode);
                bw.Write(_hardwareType);
                bw.Write(_addressLen);
                bw.Write(_hops);
                bw.Write(_transactionID);
                bw.Write(_seconds);
                bw.Write((byte)(_broadcast ? 0x80 : 0x00));
                bw.Write((byte)0x00);
                bw.Write(_clientIP);
                bw.Write(_assignedIP);
                bw.Write(_serverIP);
                bw.Write(_relayIP);
                byte[] tmp = new byte[16];
                _mac.CopyTo(tmp, 0);
                bw.Write(tmp);
                tmp = new byte[64];
                System.Text.ASCIIEncoding.ASCII.GetBytes(_serverHostName).CopyTo(tmp, 0);
                bw.Write(tmp);
                tmp = new byte[128];
                System.Text.ASCIIEncoding.ASCII.GetBytes(_file).CopyTo(tmp, 0);
                bw.Write(tmp);
                bw.Write(new byte[]{(byte)0x63,(byte)0x82,(byte)0x53,(byte)0x63});
                bw.Write((byte)DHCPOptionEnum.DHCPMessageTYPE);
                bw.Write((byte)1);
                bw.Write(this[DHCPOptionEnum.DHCPMessageTYPE]);
                foreach (DHCPOption opt in _options)
                {
                	  if (opt.Type!=DHCPOptionEnum.DHCPMessageTYPE){
	                    bw.Write((byte)opt.Type);
   	                 bw.Write((byte)opt.Value.Length);
      	              bw.Write(opt.Value);
                    }
                }
                bw.Write((byte)255);
                while (ms.Length%8!=0)
                {
                	bw.Write((byte)0x00);
                }
                return ms.ToArray();
            }
        }
    }
}
