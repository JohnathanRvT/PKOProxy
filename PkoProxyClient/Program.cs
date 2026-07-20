using System;
using System.Threading;
using System.Threading.Tasks;

namespace PkoProxyClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return;
            }

            string command = args[0].ToLower();

            if (command == "test")
            {
                bool success = PkoTest.RunTests();
                Environment.Exit(success ? 0 : 1);
            }
            else if (command == "proxy")
            {
                int localPort = 3333;
                string remoteHost = "127.0.0.1";
                int remotePort = 333;
                bool protection = false;
                string logFile = "proxy_packets.log";

                for (int i = 1; i < args.Length; i++)
                {
                    if (args[i] == "--local-port" && i + 1 < args.Length)
                        localPort = int.Parse(args[++i]);
                    else if (args[i] == "--remote-host" && i + 1 < args.Length)
                        remoteHost = args[++i];
                    else if (args[i] == "--remote-port" && i + 1 < args.Length)
                        remotePort = int.Parse(args[++i]);
                    else if (args[i] == "--protection")
                        protection = true;
                    else if (args[i] == "--log-file" && i + 1 < args.Length)
                        logFile = args[++i];
                }

                var proxy = new PkoProxy(localPort, remoteHost, remotePort, protection, logFile);
                var cts = new CancellationTokenSource();
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    eventArgs.Cancel = true;
                    cts.Cancel();
                };

                await proxy.StartAsync(cts.Token);
            }
            else if (command == "client")
            {
                string host = "127.0.0.1";
                int port = 333;
                ushort version = 100;

                for (int i = 1; i < args.Length; i++)
                {
                    if (args[i] == "--host" && i + 1 < args.Length)
                        host = args[++i];
                    else if (args[i] == "--port" && i + 1 < args.Length)
                        port = int.Parse(args[++i]);
                    else if (args[i] == "--version" && i + 1 < args.Length)
                        version = ushort.Parse(args[++i]);
                }

                var client = new PkoClient(host, port, version);
                await client.RunAsync();
            }
            else
            {
                Console.WriteLine($"Unknown command: {command}");
                PrintUsage();
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("PKO C# Multi-Tool");
            Console.WriteLine("Usage:");
            Console.WriteLine("  dotnet run -- <command> [arguments]");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  test    - Run cryptography, encoders, and binary IO tests");
            Console.WriteLine("  proxy   - Run client-side proxy to inspect & dump unencrypted packets");
            Console.WriteLine("    Arguments:");
            Console.WriteLine("      --local-port <port>    Local port to listen on (default: 3333)");
            Console.WriteLine("      --remote-host <host>   Target server IP/host (default: 127.0.0.1)");
            Console.WriteLine("      --remote-port <port>   Target server Port (default: 333)");
            Console.WriteLine("      --protection           Enable sequence number protection parsing");
            Console.WriteLine("      --log-file <file>      Log file path for dumped packets (default: proxy_packets.log)");
            Console.WriteLine();
            Console.WriteLine("  client  - Connect as a playable client to the server");
            Console.WriteLine("    Arguments:");
            Console.WriteLine("      --host <host>          Server IP/host to connect to (default: 127.0.0.1)");
            Console.WriteLine("      --port <port>          Server Port (default: 333)");
            Console.WriteLine("      --version <version>    Client game version (default: 100)");
            Console.WriteLine();
        }
    }
}
