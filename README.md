A simple .Net Framework dll that serializes and encrypts objects with a supplied password and decrypts with the same.
Class EncryptDecrypt creates a hash of the supplied password. The hash is used because the key supplied to AES needs to be a certain bitsize which is guaranteed by hashing.
The supplied object is then serialized to Json, encrpted and returned as a bye array.

For decrypt operations the EncryptDecrypt function must be wrapped in a try {} except as supplying an incorrect password will cause the decryptor to throw and exception.

Program.cs contains a simple useage example. Tests\TestCrypt includes more complex serialize\encrypt examples.
