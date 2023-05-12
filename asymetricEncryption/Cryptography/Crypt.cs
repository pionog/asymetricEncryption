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
            byte[] fileContent = null;
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs);
                
                long byteLength = new System.IO.FileInfo(fileName).Length;
                fileContent = binaryReader.ReadBytes((Int32)byteLength);
                fs.Close();
                fs.Dispose();
                binaryReader.Close();
            }
            catch (Exception ex) {
                MessageBox.Show("There occured error with reading file. Chceck if it is a proper file.");
            }
            RSA rsa = RSA.Create();

            var csp = new RSACryptoServiceProvider(4096);

            //how to get the private key
            var privKey = csp.ExportParameters(true);

            //and the public key ...
            var pubKey = csp.ExportParameters(false);
            var pubKeyBytes = Convert.ToBase64String(pubKey.Modulus);
            var publicKey = new StringBuilder();
            publicKey.AppendLine("-----BEGIN PUBLIC KEY-----");
            publicKey.AppendLine(pubKeyBytes);
            publicKey.AppendLine("-----END PUBLIC KEY-----");
            File.WriteAllText(fileName + "public_key.txt", publicKey.ToString());

            byte[] encryptedBytes = null;

            rsa.ImportParameters(pubKey);
            try
            {
                encryptedBytes = rsa.Encrypt(fileContent, System.Security.Cryptography.RSAEncryptionPadding.OaepSHA512);
                MessageBox.Show("Encryption has been ended successfully.");
            }
            catch(Exception ex)
            {
                MessageBox.Show("Program was unable to successfully encrypt this file.");
            }
            return encryptedBytes;
        }
        /*public static byte[] decrypt(string fileName) {
            byte[] fileContent = null;
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs);

                long byteLength = new System.IO.FileInfo(fileName).Length;
                fileContent = binaryReader.ReadBytes((Int32)byteLength);
                fs.Close();
                fs.Dispose();
                binaryReader.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("There occured error with reading file. Chceck if it is a proper file.");
            }
        }*/
    }
}
