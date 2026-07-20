using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkoProxyClient
{
    public class PkoClient
    {
        private readonly string _host;
        private readonly int _port;
        private readonly ushort _version;
        private TcpClient _client;
        private NetworkStream _stream;
        private PacketEncryptor _encryptor;
        private string _chapString = "";
        private string _login = "";
        private byte[] _passwordBytes = Array.Empty<byte>();
        private bool _connected = false;
        private uint _session = 0x80000000;
        private CancellationTokenSource _cts;

        public PkoClient(string host, int port, ushort version = 100)
        {
            _host = host;
            _port = port;
            _version = version;
            _encryptor = new PacketEncryptor();
        }

        public async Task RunAsync()
        {
            _client = new TcpClient();
            try
            {
                LogConsole($"Connecting to target server at {_host}:{_port}...");
                await _client.ConnectAsync(_host, _port);
                _stream = _client.GetStream();
                _connected = true;
                _cts = new CancellationTokenSource();

                LogConsole("Connected! Starting background packet receiver...");
                _ = ReceivePacketsAsync(_cts.Token);

                // Start CLI loop
                await CommandLoopAsync();
            }
            catch (Exception ex)
            {
                LogConsole($"Error: {ex.Message}");
            }
            finally
            {
                Disconnect();
            }
        }

        private void Disconnect()
        {
            _connected = false;
            _cts?.Cancel();
            _stream?.Close();
            _client?.Close();
            LogConsole("Disconnected from server.");
        }

        private async Task ReceivePacketsAsync(CancellationToken cancellationToken)
        {
            var reader = new TcpStreamPacketReader(_stream);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Check if there are 2 bytes available for heartbeat or size
                    byte[] packet = await reader.ReadPacketAsync(cancellationToken);
                    if (packet == null) break;

                    // Handle 2-byte TCP heartbeat
                    if (packet.Length == 2)
                    {
                        // Reply with 2-byte heartbeat 0x0002
                        byte[] heartbeat = new byte[] { 0, 2 };
                        await _stream.WriteAsync(heartbeat, 0, 2, cancellationToken);
                        LogConsole("[S->C] TCP Heartbeat received & answered.");
                        continue;
                    }

                    // Parse normal packet
                    byte[] copy = (byte[])packet.Clone();
                    ushort packetSize = (ushort)((copy[0] << 8) | copy[1]);
                    uint session = (uint)((copy[2] << 24) | (copy[3] << 16) | (copy[4] << 8) | copy[5]);

                    // Decrypt if encryption is enabled (excluding unencrypted 931)
                    ushort packetIdBeforeDec = 0;
                    if (!_encryptor.Enabled)
                    {
                        packetIdBeforeDec = (ushort)((copy[6] << 8) | copy[7]);
                    }

                    if (_encryptor.Enabled && packetIdBeforeDec != 931)
                    {
                        byte[] payload = new byte[copy.Length - 6];
                        Array.Copy(copy, 6, payload, 0, payload.Length);
                        _encryptor.Decrypt(payload, DecryptType.SC);
                        Array.Copy(payload, 0, copy, 6, payload.Length);
                    }

                    var pktReader = new PkoPacketReader(copy);
                    pktReader.ReadUint16(); // size
                    pktReader.ReadUint32(); // session
                    ushort packetId = pktReader.ReadUint16();

                    LogConsole($"[S->C] Packet ID: {packetId} | Size: {packetSize}");

                    if (packetId == 940) // ChapString
                    {
                        _chapString = pktReader.ReadString();
                        LogConsole($"[Handshake] Received CHAP String: \"{_chapString}\". You can now login!");
                    }
                    else if (packetId == 931) // LoginResult
                    {
                        ushort result = pktReader.ReadUint16();
                        LogConsole($"[Login] Result: {result} ({(result == 0 ? "Success" : "Failed")})");
                        if (result == 0) // result_success is 0 in PKO
                        {
                            ushort keyLen = pktReader.ReadUint16();
                            byte[] encryptionKey = pktReader.ReadBytes(keyLen);
                            pktReader.SeekFromEnd(8);
                            bool commEncryption = pktReader.ReadUint32() != 0;

                            if (commEncryption)
                            {
                                _encryptor.Init(true, _version, _chapString, _passwordBytes, encryptionKey);
                                LogConsole("[Crypto] Encryption initialized and active for this session!");
                            }
                        }
                    }
                    else if (packetId == 537) // Ping from Server
                    {
                        LogConsole("[S->C] Ping from Server. Replying with CPingPacket...");
                        await SendPingAsync(cancellationToken);
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogConsole($"Receiver stopped: {ex.Message}");
            }
            finally
            {
                Disconnect();
            }
        }

        private async Task CommandLoopAsync()
        {
            Console.WriteLine("\n=== PKO Standalone C# Playable Client ===");
            Console.WriteLine("Commands:");
            Console.WriteLine("  login <user> <password>     - Handshake and login to the server");
            Console.WriteLine("  select <character_name>     - Select character and begin play");
            Console.WriteLine("  ping                        - Send ping keep-alive packet");
            Console.WriteLine("  exit                        - Disconnect and exit");
            Console.WriteLine("=========================================\n");

            while (_connected)
            {
                Console.Write("> ");
                string line = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) continue;

                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string cmd = parts[0].ToLower();

                if (cmd == "exit")
                {
                    break;
                }
                else if (cmd == "login")
                {
                    if (parts.Length < 3)
                    {
                        Console.WriteLine("Usage: login <user> <password>");
                        continue;
                    }
                    if (string.IsNullOrEmpty(_chapString))
                    {
                        Console.WriteLine("Waiting for CHAP string from server...");
                        continue;
                    }
                    _login = parts[1];
                    string rawPassword = parts[2];

                    // Cache password in the encoded form used inside proxy server
                    _passwordBytes = PasswordEncoder.Encode(rawPassword, _chapString);

                    await SendLoginAsync(_login, rawPassword);
                }
                else if (cmd == "select")
                {
                    if (parts.Length < 2)
                    {
                        Console.WriteLine("Usage: select <character_name>");
                        continue;
                    }
                    await SendBeginPlayAsync(parts[1]);
                }
                else if (cmd == "ping")
                {
                    await SendPingAsync(_cts.Token);
                }
                else
                {
                    Console.WriteLine("Unknown command.");
                }
            }
        }

        private async Task SendLoginAsync(string user, string rawPassword)
        {
            var writer = new PkoPacketWriter();
            writer.WriteUint16(0); // Size placeholder
            writer.WriteUint32(_session);
            writer.WriteUint16(431); // Packet ID

            writer.WriteString(""); // m_nobill
            writer.WriteString(user); // m_login
            writer.WriteUint16((ushort)_passwordBytes.Length);
            writer.WriteBytes(_passwordBytes);
            writer.WriteString("00:11:22:33:44:55"); // mac address
            writer.WriteUint32(0x0100007F); // localhost IP (127.0.0.1)
            writer.WriteUint16(0); // flag
            writer.WriteUint16(_version); // version

            // Add extra 2 bytes protection version if target is local proxy or matches protect version
            writer.WriteByte(0);
            writer.WriteByte(0);

            byte[] data = writer.ToArray();
            ushort actualSize = (ushort)data.Length;
            data[0] = (byte)(actualSize >> 8);
            data[1] = (byte)(actualSize & 0xFF);

            // Encryption
            if (_encryptor.Enabled)
            {
                byte[] payload = new byte[data.Length - 6];
                Array.Copy(data, 6, payload, 0, payload.Length);
                _encryptor.Encrypt(payload, EncryptType.CS);
                Array.Copy(payload, 0, data, 6, payload.Length);
            }

            await _stream.WriteAsync(data, 0, data.Length);
            LogConsole($"[C->S] Sent AccountLogin (431) for user '{user}'");
        }

        private async Task SendBeginPlayAsync(string charName)
        {
            var writer = new PkoPacketWriter();
            writer.WriteUint16(0); // Size placeholder
            writer.WriteUint32(_session);
            writer.WriteUint16(433); // Packet ID (BeginPlay)
            writer.WriteString(charName);

            byte[] data = writer.ToArray();
            ushort actualSize = (ushort)data.Length;
            data[0] = (byte)(actualSize >> 8);
            data[1] = (byte)(actualSize & 0xFF);

            // Encryption
            if (_encryptor.Enabled)
            {
                byte[] payload = new byte[data.Length - 6];
                Array.Copy(data, 6, payload, 0, payload.Length);
                _encryptor.Encrypt(payload, EncryptType.CS);
                Array.Copy(payload, 0, data, 6, payload.Length);
            }

            await _stream.WriteAsync(data, 0, data.Length);
            LogConsole($"[C->S] Sent BeginPlay (433) selecting character '{charName}'");
        }

        private async Task SendPingAsync(CancellationToken cancellationToken)
        {
            var writer = new PkoPacketWriter();
            writer.WriteUint16(0); // Size placeholder
            writer.WriteUint32(_session);
            writer.WriteUint16(17); // Packet ID (Ping)

            byte[] data = writer.ToArray();
            ushort actualSize = (ushort)data.Length;
            data[0] = (byte)(actualSize >> 8);
            data[1] = (byte)(actualSize & 0xFF);

            // Encryption
            if (_encryptor.Enabled)
            {
                byte[] payload = new byte[data.Length - 6];
                Array.Copy(data, 6, payload, 0, payload.Length);
                _encryptor.Encrypt(payload, EncryptType.CS);
                Array.Copy(payload, 0, data, 6, payload.Length);
            }

            await _stream.WriteAsync(data, 0, data.Length, cancellationToken);
            LogConsole("[C->S] Sent PingPacket (17)");
        }

        private void LogConsole(string message)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
        }
    }
}
