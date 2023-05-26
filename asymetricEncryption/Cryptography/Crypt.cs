using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Windows;
using System.Numerics;
using System.Reflection.PortableExecutable;
using System.Buffers.Text;

namespace asymetricEncryption.Cryptography
{
    public class Crypt
    {
        static int byteSize = 256-11; //256 size of byte - 11 size of minimal padding for pkcs
        public static void encrypt(string fileName)
        {
            if(!File.Exists(fileName))
            {
                throw new FileNotFoundException("Chceck if it is a proper file.");
            }
            long howManyBlocks;
            byte[][] blocks;
            byte[]? fileContent = null;
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs, Encoding.UTF8, false);

                long byteLength = new System.IO.FileInfo(fileName).Length;
                howManyBlocks = byteLength / byteSize + 1;
                blocks = new byte[howManyBlocks][];
                for (int i = 0; i < howManyBlocks; i++) {
                    if (byteLength >= byteSize)
                    {
                        blocks[i] = binaryReader.ReadBytes(byteSize);
                    }
                    else
                    {
                        blocks[i] = binaryReader.ReadBytes((Int32)byteLength);
                    }
                    byteLength -= byteSize;
                }
                //fileContent = binaryReader.ReadBytes((Int32)byteLength);
                fs.Close();
                fs.Dispose();
                binaryReader.Close();
            }
            catch {
                throw new ArgumentException("There occured an error while reading file.");
            }

            var csp = new RSACryptoServiceProvider(2048);

            //how to get the private key
            var privKey = csp.ExportParameters(true);
            var privateKey = new StringBuilder();
            privateKey.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            privateKey.AppendLine(Convert.ToBase64String(csp.ExportRSAPrivateKey()));
            privateKey.AppendLine("-----END RSA PRIVATE KEY-----");
            File.WriteAllText(fileName + ".private_key.txt", privateKey.ToString());

            //and the public key ...
            var publicKey = new StringBuilder();
            publicKey.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            publicKey.AppendLine(Convert.ToBase64String(csp.ExportRSAPublicKey()));
            publicKey.AppendLine("-----END RSA PUBLIC KEY-----");
            File.WriteAllText(fileName + ".public_key.txt", publicKey.ToString());

            byte[][] encryptedBlocks = new byte[howManyBlocks][];
            //byte[] encryptedBytes;
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    encryptedBlocks[i] = csp.Encrypt(blocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
                //encryptedBytes = csp.Encrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully encrypt this file.");
            }
            string[] blocksText = new string[howManyBlocks];
            for (int i = 0; i < howManyBlocks; i++)
            {
                blocksText[i] = Convert.ToBase64String(encryptedBlocks[i]);
            }
            //string text = Convert.ToBase64String(encryptedBytes);
            try
            {
                using (StreamWriter writer = File.CreateText(fileName + ".encrypted"))
                {
                    for (int i = 0; i < howManyBlocks; i++)
                    {
                        writer.Write(blocksText[i]);
                    }
                }
                //File.WriteAllText(fileName + ".encrypted", text);
            }
            catch {
                throw new ArgumentException("Could not save an encrypted file");
            }
            return;
        }



        public static void decrypt(string fileName) { //filename = original file + ".encrypted"
            string originalFileName = Path.GetFileNameWithoutExtension(fileName);
            string filePath = Path.GetDirectoryName(fileName);
            string file = Path.Combine(filePath, originalFileName); //original file without ".enrypted"
            //byte[] fileContent = null;
            byte[] fileContent = new byte[1];
            string textFile;
            long howManyBlocks;
            try
            {
                using (StreamReader sr = new StreamReader(fileName, Encoding.UTF8, false))
                {
                    textFile = sr.ReadToEnd();
                }

                //string base64 = File.ReadAllText(fileName);
                //fileContent = System.Convert.FromBase64String(base64);

            }

            catch
            {
                throw new ArgumentException("Program was unable to successfully encrypt this file.");
            }
            string[] lines = textFile.Split("==");
            howManyBlocks = lines.Length - 1;
            for (int i = 0; i < howManyBlocks; i++)
            {
                lines[i] += "=="; // adding "==" characters to restore them from Split() method
            }
            byte[][] fileBlocks = new byte[howManyBlocks][];
            for (int i = 0; i < howManyBlocks; i++)
            {
                fileBlocks[i] = System.Convert.FromBase64String(lines[i]);
            }

            byte[] privateKeyContent;
            
            //reading private key
            try
            {
                string[] strings = File.ReadAllLines(file + ".private_key.txt");
                try
                {
                    string text = strings[1]; //[0] - header, [1] - private key [2] - footer
                    privateKeyContent = Convert.FromBase64String(text);
                }
                catch {
                    throw new ArgumentNullException("File containing key was modified.");
                }
            }
            catch
            {
                throw new ArgumentException("Private key is not probably in the same directory as given file.");
            }
            var csp = new RSACryptoServiceProvider(2048);
            csp.ImportRSAPrivateKey(privateKeyContent, out _);
            byte[][] decryptedBlocks = new byte[howManyBlocks][];
            //byte[]? decryptedBytes;
            byte[]? decryptedBytes = new byte[1];
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    decryptedBlocks[i] = csp.Decrypt(fileBlocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
                //decryptedBytes = csp.Decrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully encrypt this file.");
            }

            string fileBE = System.IO.Path.GetFileNameWithoutExtension(fileName);
            string fileWE = System.IO.Path.GetFileNameWithoutExtension(fileBE);
            string extension = System.IO.Path.GetExtension(file);
            string fileResult = fileWE + "_result" + extension;
            string path = System.IO.Path.GetDirectoryName(fileName);
            string fileNameDecrypted = System.IO.Path.Combine(path, fileResult);
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileNameDecrypted, System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.Write);
                System.IO.BinaryWriter binaryWriter = new System.IO.BinaryWriter(fs, Encoding.UTF8, false);

                for (int i = 0; i < howManyBlocks; i++)
                {
                     binaryWriter.Write(decryptedBlocks[i]);
                }
                //fileContent = binaryReader.ReadBytes((Int32)byteLength);
                fs.Close();
                fs.Dispose();
                binaryWriter.Close();
            }
            catch
            {
                throw new ArgumentException("There occured an error while reading file.");
            }

            //File.WriteAllBytes(fileNameDecrypted, decryptedBytes);
            return;
        }
        public static void modify(string fileName, int whichByte) {
            byte[] fileContent = null;
            string base64;
            try
            {
                base64 = File.ReadAllText(fileName);
                fileContent = System.Convert.FromBase64String(base64);
            }
            catch
            {
                throw new ArgumentException("Program was unable to successfully encrypt this file.");
            }
            fileContent[whichByte] = (byte)BitOperations.RotateLeft(fileContent[whichByte], 4);
            base64 = System.Convert.ToBase64String(fileContent);
            File.WriteAllText(fileName,base64);

            return;
        }
    }
}
