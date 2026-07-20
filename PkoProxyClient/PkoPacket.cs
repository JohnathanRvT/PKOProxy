using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkoProxyClient
{
    public class PkoPacketReader
    {
        private byte[] _data;
        private int _pos;

        public PkoPacketReader(byte[] data)
        {
            _data = data;
            _pos = 0;
        }

        public byte ReadByte()
        {
            return _data[_pos++];
        }

        public ushort ReadUint16()
        {
            ushort val = (ushort)((_data[_pos] << 8) | _data[_pos + 1]);
            _pos += 2;
            return val;
        }

        public uint ReadUint32()
        {
            uint val = (uint)((_data[_pos] << 24) | (_data[_pos + 1] << 16) | (_data[_pos + 2] << 8) | _data[_pos + 3]);
            _pos += 4;
            return val;
        }

        public string ReadString()
        {
            ushort len = ReadUint16();
            if (len == 0) return "";
            string s = Encoding.ASCII.GetString(_data, _pos, len - 1);
            _pos += len;
            return s;
        }

        public byte[] ReadBytes(int count)
        {
            byte[] buf = new byte[count];
            Array.Copy(_data, _pos, buf, 0, count);
            _pos += count;
            return buf;
        }

        public void SeekFromEnd(int offset)
        {
            _pos = _data.Length - offset;
        }

        public int Remaining => _data.Length - _pos;
    }

    public class PkoPacketWriter
    {
        private List<byte> _data = new List<byte>();

        public void WriteByte(byte b)
        {
            _data.Add(b);
        }

        public void WriteUint16(ushort val)
        {
            _data.Add((byte)(val >> 8));
            _data.Add((byte)(val & 0xFF));
        }

        public void WriteUint32(uint val)
        {
            _data.Add((byte)(val >> 24));
            _data.Add((byte)(val >> 16));
            _data.Add((byte)(val >> 8));
            _data.Add((byte)(val & 0xFF));
        }

        public void WriteString(string s)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(s);
            ushort len = (ushort)(bytes.Length + 1);
            WriteUint16(len);
            _data.AddRange(bytes);
            _data.Add(0); // null terminator
        }

        public void WriteBytes(byte[] buf)
        {
            _data.AddRange(buf);
        }

        public byte[] ToArray()
        {
            return _data.ToArray();
        }
    }

    public class TcpStreamPacketReader
    {
        private readonly NetworkStream _stream;
        private readonly byte[] _headerBuffer = new byte[2];

        public TcpStreamPacketReader(NetworkStream stream)
        {
            _stream = stream;
        }

        public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken)
        {
            int bytesRead = 0;
            while (bytesRead < 2)
            {
                int read = await _stream.ReadAsync(_headerBuffer, bytesRead, 2 - bytesRead, cancellationToken);
                if (read == 0) return null; // EOF
                bytesRead += read;
            }

            ushort size = (ushort)((_headerBuffer[0] << 8) | _headerBuffer[1]);
            if (size < 2)
                throw new InvalidDataException($"Invalid packet size: {size}");

            byte[] packet = new byte[size];
            packet[0] = _headerBuffer[0];
            packet[1] = _headerBuffer[1];

            int target = size - 2;
            int offset = 2;
            while (target > 0)
            {
                int read = await _stream.ReadAsync(packet, offset, target, cancellationToken);
                if (read == 0)
                    throw new IOException("Connection closed while reading packet body.");
                offset += read;
                target -= read;
            }

            return packet;
        }
    }
}
