using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.ComponentModel;
using System.IO;
using System.Windows;

namespace asymetricEncryption.Cryptography
{
    public class Crypt
    {
        public static byte[] encrypt(string fileName)
        {
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
            catch (Exception ex) {
                MessageBox.Show("There occured an error with reading the file. Chceck if it is a proper file.");
                throw;
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
            var pubKey = csp.ExportParameters(false);
            var publicKey = new StringBuilder();
            publicKey.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            byte[] pk = csp.ExportRSAPublicKey();
            publicKey.AppendLine(Convert.ToBase64String(pk));
            publicKey.AppendLine("-----END RSA PUBLIC KEY-----");
            File.WriteAllText(fileName + ".public_key.txt", publicKey.ToString());

            byte[] encryptedBytes = null;

            //csp.ImportParameters(pubKey);
            try
            {
                encryptedBytes = csp.Encrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                MessageBox.Show("Encryption has been ended successfully.");
            }
            catch(Exception ex)
            {
                MessageBox.Show("Program was unable to successfully encrypt this file.");
            }
            return encryptedBytes;
        }
        public static byte[] decrypt(string fileName) { //filename = original file + ".encrypted"
            string originalFileName = Path.GetFileNameWithoutExtension(fileName);
            string filePath = Path.GetDirectoryName(fileName);
            string file = Path.Combine(filePath, originalFileName); //original file without ".enrypted"
            byte[] fileContent = null;
            try
            {
               string base64 = File.ReadAllText(fileName);
                fileContent = System.Convert.FromBase64String(base64);
            }
            catch(Exception ex)
            {
                MessageBox.Show("Program was unable to successfully encrypt this file.");
            }
            byte[] privateKeyContent = null;
            
            //reading private key
            try
            {
                string[] strings = File.ReadAllLines(file + ".private_key.txt");
                string text = strings[1]; //[0] - header, [1] - private key [2] - footer
                privateKeyContent = Convert.FromBase64String(text);
            }
            catch (Exception ex)
            {
                MessageBox.Show("There occured an error with reading the private key. Chceck if there is a proper file with private key in the same directory.");
                throw;
            }

            
            RSA rsa = RSA.Create();


            //int numberOfBytes;
            /*try
            {
                rsa.ImportRSAPrivateKey(privateKeyContent, out _);
            }
            catch (Exception ex)
            {
                MessageBox.Show("There occured an error with reading the private key. Chceck if there is a proper file with private key in the same directory.");
                throw;
            }*/
            var csp = new RSACryptoServiceProvider(2048);
            csp.ImportRSAPrivateKey(privateKeyContent, out _);
            byte[]? decryptedBytes;
            RSAParameters privKey = Decode.DecodeRSAPrivateKey(privateKeyContent);
            rsa.ImportParameters(privKey);
            try
            {
                decryptedBytes = csp.Decrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                MessageBox.Show("Decryption has been ended successfully.");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Program was unable to successfully encrypt this file.");
                throw;
            }
            return decryptedBytes;
        }
    }
}
