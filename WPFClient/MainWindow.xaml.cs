using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace WPFClient
{
    public partial class MainWindow : Window
    {
        private TcpClient client;
        private StreamWriter writer;
        private StreamReader reader;
        private RSA rsaClient; 
        private RSA rsaServerPublic; 

        public MainWindow()
        {
            InitializeComponent();
            ConnectToServer();
        }

        private async void ConnectToServer()
        {
            try
            {
                client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", 9000);
                var stream = client.GetStream();
                reader = new StreamReader(stream);
                writer = new StreamWriter(stream) { AutoFlush = true };
                string base64ServerPubKey = await reader.ReadLineAsync();
                rsaServerPublic = RSA.Create();
                rsaServerPublic.ImportSubjectPublicKeyInfo(Convert.FromBase64String(base64ServerPubKey), out _);
                rsaClient = RSA.Create();
                string base64ClientPubKey = Convert.ToBase64String(rsaClient.ExportSubjectPublicKeyInfo());
                await writer.WriteLineAsync(base64ClientPubKey);
                _ = Task.Run(ReceiveMessages);
                txtChat.AppendText("Connected with RSA encryption and digital signature.\n");
            }
            catch (Exception ex)
            {
                txtChat.AppendText("Error during connection: " + ex.Message + "\n");
            }
        }

        private async Task ReceiveMessages()
        {
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
                    string message = Encoding.UTF8.GetString(rsaClient.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1));
                    bool isVerified = rsaServerPublic.VerifyData(Encoding.UTF8.GetBytes(message),signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                    if (!isVerified)
                    {
                        Dispatcher.Invoke(() => txtChat.AppendText("Unauthentic message from server!\n"));
                        continue;
                    }
                    Dispatcher.Invoke(() => txtChat.AppendText("Authenticated server: " + message + "\n"));
                }
            }
            catch { }
        }

        private async void btnSend_Click(object sender, RoutedEventArgs e)
        {
            string msg = txtMsg.Text;
            if (string.IsNullOrWhiteSpace(msg)) return;
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
                byte[] signature = rsaClient.SignData(msgBytes,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                byte[] encryptedData = rsaServerPublic.Encrypt(msgBytes, RSAEncryptionPadding.Pkcs1);
                string toSend = Convert.ToBase64String(encryptedData) + "|" + Convert.ToBase64String(signature);
                await writer.WriteLineAsync(toSend);
                Dispatcher.Invoke(() => txtChat.AppendText("You: " + msg + "\n"));
                txtMsg.Clear();
            }
            catch (Exception ex)
            {
                txtChat.AppendText("Error during sending: " + ex.Message + "\n");
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            writer?.Close();
            reader?.Close();
            client?.Close();
        }
    }
}
