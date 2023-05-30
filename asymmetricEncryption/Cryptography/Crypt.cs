using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Numerics;

namespace asymmetricEncryption.Cryptography
{
    public class Crypt
    {
        static readonly int blockSize = 256-11; //256 size of byte - 11 size of minimal padding for pkcs1
        public static void encrypt(string fileName)
        {
            if(!File.Exists(fileName))
            {
                throw new FileNotFoundException("Chceck if it is a proper file.");
            }
            long howManyBlocks;
            byte[][] blocks;
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs, Encoding.UTF8, false);

                long byteLength = new System.IO.FileInfo(fileName).Length;
                howManyBlocks = byteLength / blockSize + 1;
                blocks = new byte[howManyBlocks][];
                for (int i = 0; i < howManyBlocks; i++) {
                    if (byteLength >= blockSize)
                    {
                        blocks[i] = binaryReader.ReadBytes(blockSize);
                    }
                    else
                    {
                        blocks[i] = binaryReader.ReadBytes((Int32)byteLength);
                    }
                    byteLength -= blockSize;
                }
                fs.Close();
                fs.Dispose();
                binaryReader.Close();
            }
            catch {
                throw new ArgumentException("There occured an error while reading file.");
            }

            RSACryptoServiceProvider csp = new(2048);

            //how to get the private key
            var privKey = csp.ExportParameters(true);
            var metadataFile = new StringBuilder();

            metadataFile.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            metadataFile.AppendLine(Convert.ToBase64String(csp.ExportRSAPrivateKey()));
            metadataFile.AppendLine("-----END RSA PRIVATE KEY-----");
            byte[] extension = System.Text.Encoding.UTF8.GetBytes(Path.GetExtension(fileName));
            metadataFile.AppendLine(Convert.ToBase64String(extension)); // file extension
            metadataFile.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            metadataFile.AppendLine(Convert.ToBase64String(csp.ExportRSAPublicKey()));
            metadataFile.AppendLine("-----END RSA PUBLIC KEY-----");

            string file = Path.GetFileNameWithoutExtension(fileName) + ".mf";
            string path = Path.GetDirectoryName(fileName);
            string metadata = Path.Combine(path, file);
            File.WriteAllText(metadata, metadataFile.ToString());

            byte[][] encryptedBlocks = new byte[howManyBlocks][];
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    encryptedBlocks[i] = csp.Encrypt(blocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
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
            try
            {
                string encryptedFile = Path.Combine(path, Path.GetFileNameWithoutExtension(fileName) + ".encrypted");
                using (StreamWriter writer = File.CreateText(encryptedFile))
                {
                    for (int i = 0; i < howManyBlocks; i++)
                    {
                        writer.Write(blocksText[i]);
                    }
                }
            }
            catch {
                throw new ArgumentException("Could not save an encrypted file");
            }
            return;
        }

        public static void decrypt(string fileName) { //filename = original file (without extension!) + ".encrypted"

            string originalFileName = Path.GetFileNameWithoutExtension(fileName);
            string directory = Path.GetDirectoryName(fileName);
            string pathToMetadata = Path.Combine(directory, originalFileName + ".mf");
            byte[] ext;
            try
            {
                string[] strings = File.ReadAllLines(pathToMetadata);
                try
                {
                    string text = strings[3]; //[0] - header, [1] - private key [2] - footer, [3] - file extension, [4] - header, [5] - public key [6] - footer
                    ext = Convert.FromBase64String(text);
                }
                catch
                {
                    throw new ArgumentNullException("File containing key was modified.");
                }
            }
            catch
            {
                throw new ArgumentException("Private key is not probably in the same directory as given file.");
            }
            string fileExtension = System.Text.Encoding.UTF8.GetString(ext, 0, ext.Length);
            string file = Path.Combine(directory, originalFileName); //original file without ".enrypted"
            string textFile;
            long howManyBlocks;
            try
            {
                using (StreamReader sr = new StreamReader(fileName, Encoding.UTF8, false))
                {
                    textFile = sr.ReadToEnd();
                }
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
                string[] strings = File.ReadAllLines(pathToMetadata);
                try
                {
                    string text = strings[1]; //[0] - header, [1] - private key [2] - footer, [3] - file extension, [4] - header, [5] - public key [6] - footer
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
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    decryptedBlocks[i] = csp.Decrypt(fileBlocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully encrypt this file.");
            }
            string fileWE = System.IO.Path.GetFileNameWithoutExtension(fileName);
            string fileResult = fileWE + "_result" + fileExtension;
            string fileNameDecrypted = System.IO.Path.Combine(directory, fileResult);
            try
            {
                System.IO.FileStream fs = new System.IO.FileStream(fileNameDecrypted, System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.Write);
                System.IO.BinaryWriter binaryWriter = new System.IO.BinaryWriter(fs, Encoding.UTF8, false);

                for (int i = 0; i < howManyBlocks; i++)
                {
                     binaryWriter.Write(decryptedBlocks[i]);
                }
                fs.Close();
                fs.Dispose();
                binaryWriter.Close();
            }
            catch
            {
                throw new ArgumentException("There occured an error while reading file.");
            }
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
