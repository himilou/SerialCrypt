using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SerialCrypt
{
    public static class PasswordHelpers
    {
        const string defaultSalt = "{d182ceb3-9873-42e4-be27-a0d03988f423}";
        public static bool PasswordMatch(string hash1, string hash2)
        {
            if(hash1 == null || hash2 == null) { return false; }
            return (hash1.Equals(hash2)) ? true : false;
        }
        public static bool PasswordMatch(byte[] hash1, byte[] hash2)
        {
            if (hash1 == null || hash2 == null) { return false; }
            return (hash1.SequenceEqual(hash2)) ? true : false;
        }
        public static string GetHashedPasswordString(string password, string userSalt = "")
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password cannot be null." );
            byte[] salt = MakeSalt(userSalt);
            byte[] hashedBytes = HashPassword(password, salt);
            return Encoding.UTF8.GetString(hashedBytes);
        }
        public static byte[] GetHashedPasswordBytes(string password, string userSalt = "")
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password cannot be null.");
            byte[] salt = MakeSalt(userSalt);
            byte[] hashedBytes = HashPassword(password, salt);
            return hashedBytes;
        }
        private static byte[] MakeSalt(string userSalt = "")
        {
            string saltstart;
            if (String.IsNullOrEmpty(userSalt))
                saltstart = defaultSalt;
            else
                saltstart = userSalt;
            
            byte[] byteArray = Encoding.UTF8.GetBytes(saltstart);
            return byteArray;
        }
        private static byte[] HashPassword(string password, byte[] salt)
        {
            using (SHA256 mySHA256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltedPassword = new byte[passwordBytes.Length + salt.Length];

                // Concatenate password and salt
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, passwordBytes.Length, salt.Length);

                // Hash the concatenated password and salt
                byte[] hashedBytes = mySHA256.ComputeHash(saltedPassword);
                return hashedBytes;
            }
        }
    }
}
