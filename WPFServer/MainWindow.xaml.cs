using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Windows;

namespace WPFServer
{
    public partial class MainWindow : Window
    {
        private TcpListener listener;
        private List<ClientInfo> clients = new List<ClientInfo>();
        private RSA rsaServer;

        public MainWindow()
        {
            InitializeComponent();
            StartServer();
        }

        private class ClientInfo
        {
            public TcpClient TcpClient;
            public RSA RsaForClient; 
        }

        private async void StartServer()
        {
            listener = new TcpListener(IPAddress.Any, 9000);
            listener.Start();
            txtChat.AppendText("Server started...\n");
            rsaServer = RSA.Create();
            while (true)
            {
                TcpClient tcpClient = await listener.AcceptTcpClientAsync();
                _ = HandleClient(tcpClient);
            }
        }

        private async System.Threading.Tasks.Task HandleClient(TcpClient tcpClient)
        {
            var stream = tcpClient.GetStream();
            var reader = new StreamReader(stream);
            var writer = new StreamWriter(stream) { AutoFlush = true };
            string publicKeyServerBase64 = Convert.ToBase64String(rsaServer.ExportSubjectPublicKeyInfo());
            await writer.WriteLineAsync(publicKeyServerBase64);
            string pubKeyClientBase64 = await reader.ReadLineAsync();
            RSA rsaClient = RSA.Create();
            rsaClient.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pubKeyClientBase64), out _);
            var clientInfo = new ClientInfo()
            {
                TcpClient = tcpClient,
                RsaForClient = rsaClient
            };
            clients.Add(clientInfo);
            try
            {
                while (true)
                {
                    string received = await reader.ReadLineAsync();
                    if (received == null) break;
                    var parts = received.Split('|');
                    if (parts.Length != 2) continue;
                    byte[] encryptedData = Convert.FromBase64String(parts[0]);
                    byte[] signature = Convert.FromBase64String(parts[1]);
                    string message = Encoding.UTF8.GetString(rsaServer.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1));
                    bool isVerified = clientInfo.RsaForClient.VerifyData(Encoding.UTF8.GetBytes(message),signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                    if (!isVerified)
                    {
                        Dispatcher.Invoke(() => txtChat.AppendText("Unauthentic message from client!\n"));
                        continue;
                    }
                    Dispatcher.Invoke(() => txtChat.AppendText("Authenticated client: " + message + "\n"));
                    byte[] responseData = Encoding.UTF8.GetBytes("Server received: " + message);
                    byte[] signatureResponse = rsaServer.SignData(responseData,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                    byte[] encryptedResponse = clientInfo.RsaForClient.Encrypt(responseData, RSAEncryptionPadding.Pkcs1);
                    string toSend = Convert.ToBase64String(encryptedResponse) + "|" + Convert.ToBase64String(signatureResponse);
                    await writer.WriteLineAsync(toSend);
                }
            }
            catch { }
            finally
            {
                clients.Remove(clientInfo);
                tcpClient.Close();
            }
        }

        private async void btnSend_Click(object sender, RoutedEventArgs e)
        {
            string msg = txtMsg.Text;
            if (string.IsNullOrWhiteSpace(msg)) return;
            txtChat.AppendText("Server: " + msg + "\n");
            foreach (var client in clients)
            {
                try
                {
                    var writer = new StreamWriter(client.TcpClient.GetStream()) { AutoFlush = true };
                    byte[] messageBytes = Encoding.UTF8.GetBytes(msg);
                    byte[] signatureMsg = rsaServer.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    byte[] encryptedMsg = client.RsaForClient.Encrypt(messageBytes, RSAEncryptionPadding.Pkcs1);
                    string toSend = Convert.ToBase64String(encryptedMsg) + "|" + Convert.ToBase64String(signatureMsg);
                    await writer.WriteLineAsync(toSend);
                }
                catch { }
            }
            txtMsg.Clear();
        }
    }
}
