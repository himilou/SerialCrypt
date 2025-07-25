
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;


namespace SerialCrypt
{
    public class EncryptDecrypt
    {
        public byte[] Encrypt(object objToEncrypt, string password)
        {
            if (objToEncrypt == null)
                throw new ArgumentException(nameof(objToEncrypt) + ": Cannot be null.");
            if (String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password) + ": Parameter cannot be null or empty");
       
            byte[] pwhash = PasswordHelpers.GetHashedPasswordBytes(password);
            byte[] encBytes = null;
            byte[] IV = null;
            int IVsize = 0;
          
            MemoryStream ser = new MemoryStream();
            
            using (StreamWriter sw = new StreamWriter(ser, Encoding.UTF8, 4096, leaveOpen: true))
            {
                JsonSerializer js = new JsonSerializer();
                js.Serialize(sw, objToEncrypt);
            }

            if (ser.Length > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(objToEncrypt) + ": Size of object to encrypt too large.");
                    
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                aes.Key = pwhash;
                IV = aes.IV;
                IVsize = IV.Length;
                
                //rewind the serialization stream and write \ encrypt it to new memory stream
                ser.Position = 0;
                MemoryStream enc = new MemoryStream();
                CryptoStream cw = new CryptoStream(enc,aes.CreateEncryptor(), CryptoStreamMode.Write);
                cw.Write(ser.ToArray(), 0, (int) ser.Length);
                cw.FlushFinalBlock();

                //copy the IV and the encData to a new byte array
                encBytes = new byte[enc.Length + IVsize];
                enc.Position = 0;
                Buffer.BlockCopy(IV, 0, encBytes, 0, IVsize);
                Buffer.BlockCopy(enc.ToArray(),0,encBytes,IVsize, (int)enc.Length);
                enc.Dispose();
                ser.Dispose();
                cw.Dispose();
                aes.Dispose();
            }
            return encBytes;
        }

        public T Decrypt<T>(byte[] encByteArray, string password)
        {
            if(encByteArray == null)
                throw new ArgumentNullException(nameof(encByteArray) + ": Cannot be null.");
            if(String.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password) + ": Cannot be null or empty.");
            if(encByteArray.Length > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(encByteArray) + ": Too large to decrypt.");

            byte[] passwordBytes = PasswordHelpers.GetHashedPasswordBytes(password);
            int IVsize = 0; // IVbytes.Length;
            int encDataSize = 0;
            byte[] ivFromData;
            
            using (Aes aes = Aes.Create())
            {
                //calculate the size of the attached IV and store it.
                IVsize = aes.IV.Length;
                encDataSize = encByteArray.Length - IVsize;
                ivFromData = new byte[IVsize];
                Buffer.BlockCopy(encByteArray, 0, ivFromData, 0, IVsize);

                aes.IV = ivFromData;
                aes.Key = passwordBytes;
                //create memory stream at the offset of the data.
                MemoryStream bencr = new MemoryStream(encByteArray,IVsize, encDataSize);
                CryptoStream cr = new CryptoStream(bencr, aes.CreateDecryptor(), CryptoStreamMode.Read);
                byte[] buf = new byte[encDataSize];
                
                bool success = false;
                try
                {
                    cr.Read(buf, 0, buf.Length); //Read can throw exception on bad Aes.Key
                    success = true;
                }
                catch (Exception ex){ }
                finally
                {
                    bencr.Dispose();      
                }
                if(!success)
                    throw new CryptographicException("Could not decrypt data.");
                
                //create a new memory stream for deserialization
                MemoryStream unenc = new MemoryStream(buf);
                unenc.Position = 0;
                object outdata;
                using (StreamReader sr = new StreamReader(unenc))
                {
                    using (JsonTextReader jtr = new JsonTextReader(sr))
                    {
                        JsonSerializer ser = new JsonSerializer();
                        outdata = ser.Deserialize<T>(jtr);       
                    }
                }
                return (T)Convert.ChangeType(outdata, typeof(T));
            }
        }
    }
}
