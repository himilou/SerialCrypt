
using System;
using SerialCrypt;
using System.Collections.Generic;


namespace crypttest
{
    class MainClass
    {
        [Serializable]
        public class Data
        {
            public string name;
            public Dictionary<string, string> _credentials;
            
            public Data()
            {
                _credentials = new Dictionary<string, string>();
            }             
        }
        public static void Main(string[] args)
        {
            Data sd = new Data();
            sd.name = "ATC doesn’t care what VFR traffic is doing below 1200 ft AGL because IFR";
            sd._credentials.Add("testing", "test");
            sd._credentials.Add("Hello", "World");

            Console.WriteLine("InputData: "+ sd.name);
            foreach (var v in sd._credentials)
                Console.WriteLine(v.Key + " " + v.Value);

            string pw = "Hello World!";
            EncryptDecrypt encryptDecrypt = new EncryptDecrypt();
            byte[] benc = encryptDecrypt.Encrypt(sd, pw);

            Data d = null;
            try
            {
                d = encryptDecrypt.Decrypt<Data>(benc, pw);
            }
            catch (Exception e)
            {
                Console.WriteLine("Decryption Error: Check password and retry");
                return;
            }
             
            Console.WriteLine("Output Data: " + d.name);
            foreach(var v in d._credentials)
                Console.WriteLine(v.Key + " " + v.Value);
        }
    }
}
