using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Numerics;
using static System.Net.Mime.MediaTypeNames;
using System.Windows.Shapes;

namespace asymmetricEncryption.Cryptography
{
    public class Crypt
    {
        static readonly int blockSize = 256-11; //256 size of byte - 11 size of minimal padding for pkcs1
        public static void encrypt(string fileName)
        {
            //checking if file exists (shouldn't be used due to system dialog, where you can only choose file)
            if(!File.Exists(fileName))
            {
                throw new FileNotFoundException("Chceck if it is a proper file.");
            }
            long howManyBlocks;
            byte[][] blocks;
            try
            {
                //opening file stream so you can read content of the file
                System.IO.FileStream fs = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
                //to read content of the file you can use binary search
                System.IO.BinaryReader binaryReader = new System.IO.BinaryReader(fs, Encoding.UTF8, false);

                //size of the file
                long byteLength = new System.IO.FileInfo(fileName).Length;
                //counting how many blocks will be needed
                howManyBlocks = byteLength / blockSize + 1;
                //creating a new bytes[] array
                blocks = new byte[howManyBlocks][];
                for (int i = 0; i < howManyBlocks; i++) {
                    //if the size of current block will be fullfiled in current iteration, then it will be 245 bytes, else only remaining size
                    if (byteLength >= blockSize)
                    {
                        blocks[i] = binaryReader.ReadBytes(blockSize);
                    }
                    else
                    {
                        blocks[i] = binaryReader.ReadBytes((Int32)byteLength);
                    }
                    //decreasing total size by block size. it won't be used anymore in this program, so program can operate on this size
                    byteLength -= blockSize;
                }
                //closing stream and binaryReader
                fs.Close();
                fs.Dispose();
                binaryReader.Close();
            }
            catch {
                throw new ArgumentException("There occured an error while reading file.");
            }

            //creating new keys
            RSACryptoServiceProvider csp = new(2048);

            //creating string for a metadata file

            var metadataFile = new StringBuilder();

            //private key with key encoded in base64
            metadataFile.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            metadataFile.AppendLine(Convert.ToBase64String(csp.ExportRSAPrivateKey()));
            metadataFile.AppendLine("-----END RSA PRIVATE KEY-----");

            //file extension encoded in base64
            byte[] extension = System.Text.Encoding.UTF8.GetBytes(System.IO.Path.GetExtension(fileName));
            metadataFile.AppendLine(Convert.ToBase64String(extension)); // file extension
            
            //public key with key encoded in base64
            metadataFile.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            metadataFile.AppendLine(Convert.ToBase64String(csp.ExportRSAPublicKey()));
            metadataFile.AppendLine("-----END RSA PUBLIC KEY-----");


            //getting metadata file path and name and saving it on drive
            string file = System.IO.Path.GetFileNameWithoutExtension(fileName) + ".mf";
            string path = System.IO.Path.GetDirectoryName(fileName);
            string metadata = System.IO.Path.Combine(path, file);
            File.WriteAllText(metadata, metadataFile.ToString());

            //new blocks for encrypted content
            byte[][] encryptedBlocks = new byte[howManyBlocks][];
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    //encrypting each block
                    encryptedBlocks[i] = csp.Encrypt(blocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully encrypt this file.");
            }
            //creating string array, so encrypted blocks can be stored in base64 format
            string[] blocksText = new string[howManyBlocks];
            for (int i = 0; i < howManyBlocks; i++)
            {
                blocksText[i] = Convert.ToBase64String(encryptedBlocks[i]);
            }
            try
            {
                string encryptedFile = System.IO.Path.Combine(path, System.IO.Path.GetFileNameWithoutExtension(fileName) + ".encrypted");
                using (StreamWriter writer = File.CreateText(encryptedFile))
                {
                    for (int i = 0; i < howManyBlocks; i++)
                    {
                        //writing metadata file
                        writer.Write(blocksText[i]);
                    }
                }
            }
            catch {
                throw new ArgumentException("Could not save an encrypted file");
            }
            return;
        }

        public static void decrypt(string fileName) { //filename = original file + ".encrypted"

            //removing extension from the string
            string originalFileName = System.IO.Path.GetFileNameWithoutExtension(fileName);
            //getting directory from the path
            string directory = System.IO.Path.GetDirectoryName(fileName);
            //path do metadata file
            string pathToMetadata = System.IO.Path.Combine(directory, originalFileName + ".mf");
            byte[] ext;
            try
            {
                //reading metadata file
                string[] strings = File.ReadAllLines(pathToMetadata);
                try
                {
                    //getting file extension
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
            //149-174 reading encryped file
            string fileExtension = System.Text.Encoding.UTF8.GetString(ext, 0, ext.Length);
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
                throw new ArgumentException("Program was unable to successfully decrypt this file.");
            }
            string[] lines = textFile.Split("==");
            //number of "==" occurance + 1 equals the number of blocks that were encrypted
            howManyBlocks = lines.Length - 1;
            for (int i = 0; i < howManyBlocks; i++)
            {
                lines[i] += "=="; // adding "==" characters to restore them from Split() method
            }
            byte[][] fileBlocks = new byte[howManyBlocks][];
            for (int i = 0; i < howManyBlocks; i++)
            {
                //reading encrypted strings in base64 to byte[] array and converting them to standard byte[]
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
            //creating new keys and importing the private key
            var csp = new RSACryptoServiceProvider(2048);
            csp.ImportRSAPrivateKey(privateKeyContent, out _);
            //odszyfrowywanie pliku
            byte[][] decryptedBlocks = new byte[howManyBlocks][];
            try
            {
                for (int i = 0; i < howManyBlocks; i++) {
                    decryptedBlocks[i] = csp.Decrypt(fileBlocks[i], System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                }
            }
            catch
            {
                throw new CryptographicException("Program was unable to successfully decrypt this file.");
            }
            //zapisanie pliku do postaci sprzed szyfrowania
            string fileWE = System.IO.Path.GetFileNameWithoutExtension(fileName);
            string fileResult = fileWE + "_result" + fileExtension;
            string fileNameDecrypted = System.IO.Path.Combine(directory, fileResult);
            try
            {
                //file stream and binaryWriter
                System.IO.FileStream fs = new System.IO.FileStream(fileNameDecrypted, System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.Write);
                System.IO.BinaryWriter binaryWriter = new System.IO.BinaryWriter(fs, Encoding.UTF8, false);

                for (int i = 0; i < howManyBlocks; i++)
                {
                    //writing each block to the decrypted file
                     binaryWriter.Write(decryptedBlocks[i]);
                }
                //closing file stream and binaryWriter
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
                throw new ArgumentException("Program was unable to successfully modify this file.");
            }
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
            //number of "==" occurance + 1 equals the number of blocks that were encrypted
            howManyBlocks = lines.Length - 1;
            for (int i = 0; i < howManyBlocks; i++)
            {
                lines[i] += "=="; // adding "==" characters to restore them from Split() method
            }
            byte[][] fileBlocks = new byte[howManyBlocks][];
            for (int i = 0; i < howManyBlocks; i++)
            {
                //reading encrypted strings in base64 to byte[] array and converting them to standard byte[]
                fileBlocks[i] = System.Convert.FromBase64String(lines[i]);
            }
            int lastBlockSize = fileBlocks[howManyBlocks- 1].Length; 
            long totalSize = (howManyBlocks-1) * blockSize + lastBlockSize;
            if (whichByte < 0 || whichByte > totalSize)
            {
                throw new ArgumentException("Provided byte could not be found.");
            }
            else {
                int i = 1;
                while (whichByte > blockSize * i) {
                    i++;
                }
                fileBlocks[i-1][whichByte - (blockSize * (i - 1))] = (byte)BitOperations.RotateLeft(fileBlocks[i-1][whichByte - (blockSize*(i-1))], 4);
            }
            string[] blocksText = new string[howManyBlocks];
            for (int i = 0; i < howManyBlocks; i++)
            {
                blocksText[i] = Convert.ToBase64String(fileBlocks[i]);
            }
            try
            {
                using (StreamWriter writer = File.CreateText(fileName))
                {
                    for (int i = 0; i < howManyBlocks; i++)
                    {
                        //writing metadata file
                        writer.Write(blocksText[i]);
                    }
                }
            }
            catch
            {
                throw new ArgumentException("Could not save an encrypted file");
            }
            return;
        }
    }
}
