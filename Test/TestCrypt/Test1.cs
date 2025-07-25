using SerialCrypt;

namespace CryptTests
{
    [TestClass]
    public sealed class PasswordHashTests
    {
        [TestMethod]
        public void StringHashEqual()
        {
            string password1 = "password";
            string password2 = "password";
            string salt = "oijsdfdolkm234r";

            string return1 = PasswordHelpers.GetHashedPasswordString(password1);
            string return2 = PasswordHelpers.GetHashedPasswordString(password2);
            Assert.AreEqual(return2, return1);

            return1 = PasswordHelpers.GetHashedPasswordString(password1, salt);
            return2 = PasswordHelpers.GetHashedPasswordString(password2, salt);
            Assert.AreEqual(return2, return1);
        }
        [TestMethod]
        public void ByteHashEqual()
        {
            string password1 = "asdfghjk1234";
            string password2 = "asdfghjk1234";
            string salt = "oijsdfdolkm234r49iu6590";

            byte[] return1 = PasswordHelpers.GetHashedPasswordBytes(password1);
            byte[] return2 = PasswordHelpers.GetHashedPasswordBytes(password2);
            Assert.IsTrue(return2.SequenceEqual(return1));

            byte[] return3 = PasswordHelpers.GetHashedPasswordBytes(password1, salt);
            byte[] return4 = PasswordHelpers.GetHashedPasswordBytes(password2, salt);
            Assert.IsTrue(return3.SequenceEqual(return4));
        }

        [TestMethod]
        public void SaltTest()
        {
            string password1 = "asdfghjk1234";
            string password2 = "asdfghjk1234";
            string salt = "oijsdfdolkm234r49iu6590";

            byte[] return1 = PasswordHelpers.GetHashedPasswordBytes(password1);
            byte[] return2 = PasswordHelpers.GetHashedPasswordBytes(password2, salt);
            Assert.IsFalse(return2.SequenceEqual(return1));
        }

        [TestMethod]
        public void ComparoratorByteTests()
        {
            string password1 = "asdfghjk1234";
            string password2 = "asdfghjk1234";
            string password3 = "zxcv@#$%22";
            string salt = "oijsdfdolkm234r49iu6590";

            byte[] return1 = PasswordHelpers.GetHashedPasswordBytes(password1);
            byte[] return2 = PasswordHelpers.GetHashedPasswordBytes(password2);
            Assert.IsTrue(PasswordHelpers.PasswordMatch(return1, return2));

            byte[] return3 = PasswordHelpers.GetHashedPasswordBytes(password1, salt);
            byte[] return4 = PasswordHelpers.GetHashedPasswordBytes(password2, salt);
            Assert.IsTrue(PasswordHelpers.PasswordMatch(return3, return4)); 

            byte[] return5 = PasswordHelpers.GetHashedPasswordBytes(password1, salt);
            byte[] return6 = PasswordHelpers.GetHashedPasswordBytes(password3, salt);
            Assert.IsFalse(PasswordHelpers.PasswordMatch(return5, return6));

            byte[] return7 = PasswordHelpers.GetHashedPasswordBytes(password2);
            byte[] return8 = PasswordHelpers.GetHashedPasswordBytes(password3);
            Assert.IsFalse(PasswordHelpers.PasswordMatch(return7, return8));

            Assert.IsFalse(PasswordHelpers.PasswordMatch(return1, return3));
        }

        [TestMethod]
        public void ComparoratorStringTests()
        {
            string password1 = "asdfghjk1234";
            string password2 = "asdfghjk1234";
            string password3 = "zxcv@#$%22";
            string salt = "oijsdfdolkm234r49iu6590";

            string return1 = PasswordHelpers.GetHashedPasswordString(password1);
            string return2 = PasswordHelpers.GetHashedPasswordString(password2);
            Assert.IsTrue(PasswordHelpers.PasswordMatch(return1, return2));

            string return3 = PasswordHelpers.GetHashedPasswordString(password1, salt);
            string return4 = PasswordHelpers.GetHashedPasswordString(password2, salt);
            Assert.IsTrue(PasswordHelpers.PasswordMatch(return3, return4));

            string return5 = PasswordHelpers.GetHashedPasswordString(password1, salt);
            string return6 = PasswordHelpers.GetHashedPasswordString(password3, salt);
            Assert.IsFalse(PasswordHelpers.PasswordMatch(return5, return6));

            string return7 = PasswordHelpers.GetHashedPasswordString(password2);
            string return8 = PasswordHelpers.GetHashedPasswordString(password3);
            Assert.IsFalse(PasswordHelpers.PasswordMatch(return7, return8));

            Assert.IsFalse(PasswordHelpers.PasswordMatch(return1, return3));
        }
    }
}
