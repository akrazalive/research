using System;
using System.IO;
using System.Security.Cryptography;



public class DES_Class
{
    private
        byte[] encrypted;
    string roundtrip;

    public DES_Class()
    {
    }
 
    public void performDES(string text)
    {
        DES myDes = DES.Create();

        // Encrypt the string to an array of bytes
        encrypted = DES_Class.EncryptStringToBytes_Des(text, myDes.Key, myDes.IV);
        // Decrypt the bytes to a string.
        roundtrip = DES_Class.DecryptStringFromBytes_Des(encrypted, myDes.Key, myDes.IV);

    }

    static byte[] EncryptStringToBytes_Des(string plainText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        byte[] encrypted;
        // Create an Aes object
        // with the specified key and IV.
        using (DES desAlg = DES.Create())
        {
            desAlg.Key = Key;
            desAlg.IV = IV;
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);
            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor,
                CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }
    static string DecryptStringFromBytes_Des(byte[] cipherText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;
        // Create an Aes object
        // with the specified key and IV.
        using (DES desAlg = DES.Create())
        {
            desAlg.Key = Key;
            desAlg.IV = IV;
            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);
            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor,
                CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        return plaintext;
    }

}
