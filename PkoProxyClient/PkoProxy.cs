using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PkoProxyClient
{
    public class HandshakeState
    {
        public string ChapString { get; set; } = "";
        public string Login { get; set; } = "";
        public byte[] PasswordBytes { get; set; } = Array.Empty<byte>();
        public ushort Version { get; set; } = 0;
    }

    public class PkoProxy
    {
        private readonly int _localPort;
        private readonly string _remoteHost;
        private readonly int _remotePort;
        private readonly bool _protectionEnabled;
        private readonly string _logFilePath;
        private TcpListener _listener;
        private int _connectionCounter = 0;

        public PkoProxy(int localPort, string remoteHost, int remotePort, bool protectionEnabled, string logFilePath = "proxy_packets.log")
        {
            _localPort = localPort;
            _remoteHost = remoteHost;
            _remotePort = remotePort;
            _protectionEnabled = protectionEnabled;
            _logFilePath = logFilePath;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _listener = new TcpListener(IPAddress.Any, _localPort);
            _listener.Start();

            LogConsole($"Proxy started. Listening on port {_localPort}, forwarding to {_remoteHost}:{_remotePort}...");
            LogConsole($"Packet sequence protection: {(_protectionEnabled ? "ENABLED" : "DISABLED")}");
            LogConsole($"Logging unencrypted packets to: {Path.GetFullPath(_logFilePath)}\n");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken);
                    int connId = Interlocked.Increment(ref _connectionCounter);
                    _ = HandleConnectionAsync(client, connId, cancellationToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogConsole($"Proxy listener encountered an error: {ex.Message}");
            }
            finally
            {
                _listener.Stop();
                LogConsole("Proxy stopped.");
            }
        }

        private async Task HandleConnectionAsync(TcpClient client, int connId, CancellationToken cancellationToken)
        {
            LogConsole($"[Connection #{connId}] Client connected from {client.Client.RemoteEndPoint}");

            using (client)
            using (TcpClient server = new TcpClient())
            {
                try
                {
                    await server.ConnectAsync(_remoteHost, _remotePort, cancellationToken);
                    LogConsole($"[Connection #{connId}] Connected to target server at {_remoteHost}:{_remotePort}");

                    using (NetworkStream clientStream = client.GetStream())
                    using (NetworkStream serverStream = server.GetStream())
                    {
                        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                        // Stateful crypto parameters for this connection
                        HandshakeState handshakeState = new HandshakeState();
                        PacketEncryptor encryptor = new PacketEncryptor();

                        // Task for Client to Server direction
                        var clientToServerTask = ForwardClientToServerAsync(clientStream, serverStream, connId, encryptor, handshakeState, cts.Token);

                        // Task for Server to Client direction
                        var serverToClientTask = ForwardServerToClientAsync(serverStream, clientStream, connId, encryptor, handshakeState, cts.Token);

                        await Task.WhenAny(clientToServerTask, serverToClientTask);
                        cts.Cancel();
                    }
                }
                catch (Exception ex)
                {
                    LogConsole($"[Connection #{connId}] Connection closed due to error: {ex.Message}");
                }
                finally
                {
                    LogConsole($"[Connection #{connId}] Disconnected.");
                }
            }
        }

        private async Task ForwardClientToServerAsync(NetworkStream clientStream, NetworkStream serverStream, int connId, PacketEncryptor encryptor, HandshakeState state, CancellationToken cancellationToken)
        {
            var reader = new TcpStreamPacketReader(clientStream);

            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] packet = await reader.ReadPacketAsync(cancellationToken);
                if (packet == null) break;

                // Handle 2-byte heartbeat packet
                if (packet.Length == 2)
                {
                    await serverStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
                    continue;
                }

                // Log raw ciphertext header/ID bytes for diagnosis
                StringBuilder rawHex = new StringBuilder();
                for (int i = 0; i < Math.Min(16, packet.Length); i++)
                {
                    rawHex.Append($"{packet[i]:X2} ");
                }
                LogConsole($"[Connection #{connId}] [Raw C->S Ciphertext] Size: {packet.Length} | Bytes: {rawHex}");

                // Parse/Inspect packet copy before forwarding
                byte[] copy = (byte[])packet.Clone();
                ushort packetSize = (ushort)((copy[0] << 8) | copy[1]);
                uint session = (uint)((copy[2] << 24) | (copy[3] << 16) | (copy[4] << 8) | copy[5]);

                // Decrypt if encryption has been enabled
                if (encryptor.Enabled)
                {
                    // Copy bytes for decryption from index 6 onwards
                    byte[] payload = new byte[copy.Length - 6];
                    Array.Copy(copy, 6, payload, 0, payload.Length);

                    encryptor.Decrypt(payload, DecryptType.CS);

                    // Reconstruct decrypted copy
                    Array.Copy(payload, 0, copy, 6, payload.Length);
                }

                var pktReader = new PkoPacketReader(copy);
                pktReader.ReadUint16(); // Skip size
                pktReader.ReadUint32(); // Skip session
                ushort packetId = pktReader.ReadUint16();

                // Handle specific handshake packets to capture info
                if (packetId == 431) // AccountLogin
                {
                    try
                    {
                        // Structure of 431: string nobill, string login, ushort pwd_len, bytes password, string mac, uint32 ip, ushort flag, ushort version
                        string nobill = pktReader.ReadString();
                        string loginVal = pktReader.ReadString();
                        ushort pwdLen = pktReader.ReadUint16();
                        byte[] pwdBytes = pktReader.ReadBytes(pwdLen);
                        string mac = pktReader.ReadString();
                        uint ip = pktReader.ReadUint32();
                        ushort flag = pktReader.ReadUint16();
                        ushort versionVal = pktReader.ReadUint16();

                        StringBuilder pwdHex = new StringBuilder();
                        foreach (byte b in pwdBytes) pwdHex.Append($"{b:X2} ");
                        LogConsole($"[Connection #{connId}] Captured pwdBytes ({pwdBytes.Length} bytes): {pwdHex}");

                        lock (state)
                        {
                            state.Login = loginVal;
                            state.PasswordBytes = pwdBytes;
                            state.Version = versionVal;
                        }

                        LogConsole($"[Connection #{connId}] [C->S Handshake Info] Intercepted Login: {loginVal}, Version: {versionVal}, Mac: {mac}");
                    }
                    catch (Exception ex)
                    {
                        LogConsole($"[Connection #{connId}] [C->S Parse Error ID 431] {ex.Message}");
                    }
                }

                // Log decrypted packet
                LogPacketDump("C -> S", connId, packetId, session, copy);

                // Forward unmodified packet to server
                await serverStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
            }
        }

        private async Task ForwardServerToClientAsync(NetworkStream serverStream, NetworkStream clientStream, int connId, PacketEncryptor encryptor, HandshakeState state, CancellationToken cancellationToken)
        {
            var reader = new TcpStreamPacketReader(serverStream);

            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] packet = await reader.ReadPacketAsync(cancellationToken);
                if (packet == null) break;

                // Handle 2-byte heartbeat packet
                if (packet.Length == 2)
                {
                    await clientStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
                    continue;
                }

                // Log raw ciphertext header/ID bytes for diagnosis
                StringBuilder rawHex = new StringBuilder();
                for (int i = 0; i < Math.Min(16, packet.Length); i++)
                {
                    rawHex.Append($"{packet[i]:X2} ");
                }
                LogConsole($"[Connection #{connId}] [Raw S->C Ciphertext] Size: {packet.Length} | Bytes: {rawHex}");

                // Parse/Inspect packet copy before forwarding
                byte[] copy = (byte[])packet.Clone();
                ushort packetSize = (ushort)((copy[0] << 8) | copy[1]);
                uint session = (uint)((copy[2] << 24) | (copy[3] << 16) | (copy[4] << 8) | copy[5]);

                // Decrypt if encryption has been enabled (excluding 931 which is not encrypted itself)
                ushort packetIdBeforeDec = 0;
                if (!encryptor.Enabled)
                {
                    packetIdBeforeDec = (ushort)((copy[6] << 8) | copy[7]);
                }

                if (encryptor.Enabled && packetIdBeforeDec != 931)
                {
                    // Copy bytes for decryption from index 6 onwards
                    byte[] payload = new byte[copy.Length - 6];
                    Array.Copy(copy, 6, payload, 0, payload.Length);

                    encryptor.Decrypt(payload, DecryptType.SC);

                    // Reconstruct decrypted copy
                    Array.Copy(payload, 0, copy, 6, payload.Length);
                }

                var pktReader = new PkoPacketReader(copy);
                pktReader.ReadUint16(); // Skip size
                pktReader.ReadUint32(); // Skip session
                ushort packetId = pktReader.ReadUint16();

                // Inspect Server Handshake Packets
                if (packetId == 940) // ChapString
                {
                    try
                    {
                        string chapString = pktReader.ReadString();
                        lock (state)
                        {
                            state.ChapString = chapString;
                        }
                        LogConsole($"[Connection #{connId}] [S->C ChapString] Intercepted Value: \"{chapString}\"");
                    }
                    catch (Exception ex)
                    {
                        LogConsole($"[Connection #{connId}] [S->C Parse Error ID 940] {ex.Message}");
                    }
                }
                else if (packetId == 931) // LoginResult (sent unencrypted)
                {
                    try
                    {
                        ushort result = pktReader.ReadUint16();
                        LogConsole($"[Connection #{connId}] [S->C LoginResult] Result Code: {result}");

                        if (result == 0) // result_success is 0 in PKO
                        {
                            ushort keyLen = pktReader.ReadUint16();
                            byte[] encryptionKey = pktReader.ReadBytes(keyLen);
                            pktReader.SeekFromEnd(8);
                            uint commEncryptionVal = pktReader.ReadUint32();
                            bool commEncryption = commEncryptionVal != 0;

                            StringBuilder keyHex = new StringBuilder();
                            foreach (byte b in encryptionKey) keyHex.Append($"{b:X2} ");
                            LogConsole($"[Connection #{connId}] [S->C Crypto Handshake] CommEncryption: {commEncryption}, Key ({encryptionKey.Length} bytes): {keyHex}");

                            if (commEncryption)
                            {
                                lock (state)
                                {
                                    if (string.IsNullOrEmpty(state.Login) || state.PasswordBytes.Length == 0)
                                    {
                                        LogConsole($"[Connection #{connId}] [Warning] Crypto handshake enabled, but login/password was not captured!");
                                    }
                                    else
                                    {
                                        encryptor.Init(true, state.Version, state.ChapString, state.PasswordBytes, encryptionKey);
                                        LogConsole($"[Connection #{connId}] [Success] Decryption engine initialized and enabled for all subsequent packets!");
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogConsole($"[Connection #{connId}] [S->C Parse Error ID 931] {ex.Message}");
                    }
                }

                // Log decrypted packet
                LogPacketDump("S -> C", connId, packetId, session, copy);

                // Forward unmodified packet to client
                await clientStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
            }
        }

        private readonly object _consoleLock = new object();

        private void LogConsole(string message)
        {
            lock (_consoleLock)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
            }
        }

        private void LogPacketDump(string direction, int connId, ushort packetId, uint session, byte[] decryptedPacket)
        {
            ushort size = (ushort)((decryptedPacket[0] << 8) | decryptedPacket[1]);
            byte[] payload = new byte[decryptedPacket.Length - 8];
            Array.Copy(decryptedPacket, 8, payload, 0, payload.Length);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"=========================================================================");
            sb.AppendLine($"[Connection #{connId}] {direction} | Packet ID: {packetId} | Size: {size} | Session: 0x{session:X8}");
            sb.AppendLine($"-------------------------------------------------------------------------");
            sb.AppendLine(HexDump(payload));
            sb.AppendLine();

            string text = sb.ToString();

            // Print summary to console
            LogConsole($"{direction} | ID: {packetId,3} | Size: {size,4} | Session: 0x{session:X8}");

            // Write detailed dump to log file
            try
            {
                lock (_logFilePath)
                {
                    File.AppendAllText(_logFilePath, text);
                }
            }
            catch { }
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i += bytesPerLine)
            {
                int chunkLength = Math.Min(bytesPerLine, bytes.Length - i);
                sb.Append($"{i:X4}: ");
                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j < chunkLength)
                        sb.Append($"{bytes[i + j]:X2} ");
                    else
                        sb.Append("   ");
                }
                sb.Append("  ");
                for (int j = 0; j < chunkLength; j++)
                {
                    char c = (char)bytes[i + j];
                    if (c >= 32 && c <= 126)
                        sb.Append(c);
                    else
                        sb.Append('.');
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }
}
