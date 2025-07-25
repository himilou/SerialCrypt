
using System.Security.Cryptography;
using SerialCrypt;


namespace CryptTests
{
  
    [TestClass]
    public sealed class SerializeObjectTests
    {
        [TestMethod]
        public void SerializeClassTest()
        {
            string password = "password";
            TestClassString stringclass1 = new TestClassString();
            TestClassString stringclass2 = new TestClassString();
            Assert.IsTrue(0 == stringclass1.CompareTo(stringclass2));

            EncryptDecrypt ed = new EncryptDecrypt();
            byte[] encbytes1 = ed.Encrypt(stringclass1, password);
            TestClassString stringclass3 = ed.Decrypt<TestClassString>(encbytes1, password);
            Assert.IsTrue(0 == stringclass1.CompareTo(stringclass3));
        }

        [TestMethod]
        public void SerializeClassComplex()
        {
            string password = "password";
            string testname = "test";
            Data data1 = new Data(testname);
            Data data2 = new Data(testname);

            bool testval = data1.Equals(data2);
            Assert.IsTrue(testval);

            EncryptDecrypt ed = new EncryptDecrypt();
            byte[] encbytes1 = ed.Encrypt(data1, password);
            Data data3 = ed.Decrypt<Data>(encbytes1, password);
            Assert.IsTrue(data1.Equals(data3));

            List<Data> list = new List<Data>();
            list.Add(data1);
            list.Add(data2);

            byte[] encbytes2 = ed.Encrypt(list, password);
            List<Data> list2 = ed.Decrypt<List<Data>>(encbytes2, password);
            Assert.IsTrue(list2.SequenceEqual(list));
        }

        [TestMethod]
        public void SerializeClassBadPwTest()
        {
            string password1 = "password";
            string password2 = "asdQWER@";
            TestClassString stringclass1 = new TestClassString();
            TestClassString stringclass2 = new TestClassString();
            Assert.IsTrue(0 == stringclass1.CompareTo(stringclass2));

            EncryptDecrypt ed = new EncryptDecrypt();
            byte[] encbytes1 = ed.Encrypt(stringclass1, password1);

            Assert.ThrowsException<CryptographicException>( ()=> ed.Decrypt<TestClassString>(encbytes1, password2));
        }
    }

    public class TestClassString : IComparable<TestClassString>
    {
        string teststring1 = "Hello World";
        string teststring2 = "Hello C#";
        public int CompareTo(TestClassString other)
        {
            if (0 == this.teststring1.CompareTo(other.teststring1))
            {
                if (0 == this.teststring2.CompareTo(other.teststring2))
                    return 0;
                else
                    return 1;
            }
            else
                return (-1);
        }
    }

    public class Data : IEquatable<Data>
    {
        public string name { get; set; }
        public List<string> tags { get; set; }
        public Dictionary<string, string> userData { get; set; }
        public Data(string name)
        {
            this.name = name;
            tags = new List<string>();
            tags.Add("value1");
            tags.Add("value2");

            userData = new Dictionary<string, string>();
            userData.Add("key1", "hello");
            userData.Add("key2", "worlds");
        }

        bool IEquatable<Data>.Equals(Data other)
        {
            return Compare(other);
        }

        public override bool Equals(object obj)
        {
            //JsonSerialize calls Equals with a component of the Data class vs the entire class.
            //This will result in a null object.
            Data other = obj as Data;
            if(other == null) return false; 
            return Compare(other);
        }

        public override int GetHashCode()
        {
            string ts = this.ToString();
            return ts.GetHashCode();
        }

        private bool Compare(Data other)
        {
            if (!String.Equals(this.name, other.name))
                return false;
            if (!this.tags.SequenceEqual(other.tags))
                return false;
            if (!this.userData.SequenceEqual(other.userData))
                return false;
            return true;
        }

        public override string ToString()
        {
            string ts = ("DataName: " + name) +
                        ("\nTags:");
            foreach (string s in tags)
                ts += ("\n\t" + s);

            ts += ("\nUserData:");
            foreach (var d in userData)
                ts += ("\n\t" + d.Key + "\t" + d.Value);
            ts += "\n";

            return ts;
        }

        
    }
}