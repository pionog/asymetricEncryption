﻿using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Windows;
using System.Numerics;

namespace asymetricEncryption.Cryptography
{
    public class Crypt
    {
        public static void encrypt(string fileName)
        {
            if(!File.Exists(fileName))
            {
                throw new FileNotFoundException("Chceck if it is a proper file.");
            }
            byte[]? fileContent = null;
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs, Encoding.UTF8, false);

                long byteLength = new System.IO.FileInfo(fileName).Length;
                fileContent = binaryReader.ReadBytes((Int32)byteLength);
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

            byte[] encryptedBytes;
            try
            {
                encryptedBytes = csp.Encrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully encrypt this file.");
            }
            string text = Convert.ToBase64String(encryptedBytes);
            try
            {
                File.WriteAllText(fileName + ".encrypted", text);
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
            byte[] fileContent = null;
            try
            {
               string base64 = File.ReadAllText(fileName);
                fileContent = System.Convert.FromBase64String(base64);
            }
            catch
            {
                throw new ArgumentException("Program was unable to successfully encrypt this file.");
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
            byte[]? decryptedBytes;
            try
            {
                decryptedBytes = csp.Decrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
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
            File.WriteAllBytes(fileNameDecrypted, decryptedBytes);
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
