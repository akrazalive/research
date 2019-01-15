using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionMethods
{
    class ChilkatLibraryMethods
    {

        public static void ECC_SHared_secret()
        {
            bool success;

            //  -----------------------------------------------------------------
            //  (Client-Side) Generate an ECC key, save the public part to a file.
            //  -----------------------------------------------------------------
            Chilkat.Prng prngClient = new Chilkat.Prng();
            Chilkat.Ecc eccClient = new Chilkat.Ecc();
            Chilkat.PrivateKey privKeyClient = eccClient.GenEccKey("secp256r1", prngClient);
            if (eccClient.LastMethodSuccess != true)
            {
                Console.WriteLine(eccClient.LastErrorText);
                return;
            }

            Chilkat.PublicKey pubKeyClient = privKeyClient.GetPublicKey();
            pubKeyClient.SavePemFile(false, "qa_output/eccClientPub.pem");

            //  -----------------------------------------------------------------
            //  (Server-Side) Generate an ECC key, save the public part to a file.
            //  -----------------------------------------------------------------
            Chilkat.Prng prngServer = new Chilkat.Prng();
            Chilkat.Ecc eccServer = new Chilkat.Ecc();
            Chilkat.PrivateKey privKeyServer = eccServer.GenEccKey("secp256r1", prngServer);
            if (eccServer.LastMethodSuccess != true)
            {
                Console.WriteLine(eccServer.LastErrorText);
                return;
            }

            Chilkat.PublicKey pubKeyServer = privKeyServer.GetPublicKey();
            pubKeyServer.SavePemFile(false, "qa_output/eccServerPub.pem");

            //  -----------------------------------------------------------------
            //  (Client-Side) Generate the shared secret using our private key, and the other's public key.
            //  -----------------------------------------------------------------

            //  Imagine that the server sent the public key PEM to the client.
            //  (This is simulated by loading the server's public key from the file.
            Chilkat.PublicKey pubKeyFromServer = new Chilkat.PublicKey();
            pubKeyFromServer.LoadFromFile("qa_output/eccServerPub.pem");
            string sharedSecret1 = eccClient.SharedSecretENC(privKeyClient, pubKeyFromServer, "base64");

            //  -----------------------------------------------------------------
            //  (Server-Side) Generate the shared secret using our private key, and the other's public key.
            //  -----------------------------------------------------------------

            //  Imagine that the client sent the public key PEM to the server.
            //  (This is simulated by loading the client's public key from the file.
            Chilkat.PublicKey pubKeyFromClient = new Chilkat.PublicKey();
            pubKeyFromClient.LoadFromFile("qa_output/eccClientPub.pem");
            string sharedSecret2 = eccServer.SharedSecretENC(privKeyServer, pubKeyFromClient, "base64");

            //  ---------------------------------------------------------
            //  Examine the shared secrets.  They should be the same.
            //  Both sides now have a secret that only they know.
            //  ---------------------------------------------------------
            Console.WriteLine(sharedSecret1);
            Console.WriteLine(sharedSecret2);
        }

        public static void performRSA(string text)
        {
            Chilkat.Rsa rsa = new Chilkat.Rsa();

bool success = rsa.UnlockComponent("Anything for 30-day trial");
if (success != true) {
    Console.WriteLine("RSA component unlock failed");
    return;
}

//  This example also generates the public and private
//  keys to be used in the RSA encryption.
//  Normally, you would generate a key pair once,
//  and distribute the public key to your partner.
//  Anything encrypted with the public key can be
//  decrypted with the private key.  The reverse is
//  also true: anything encrypted using the private
//  key can be decrypted using the public key.

//  Generate a 1024-bit key.  Chilkat RSA supports
//  key sizes ranging from 512 bits to 4096 bits.
success = rsa.GenerateKey(1024);
if (success != true) {
    Console.WriteLine(rsa.LastErrorText);
    return;
}

//  Keys are exported in XML format:
string publicKey = rsa.ExportPublicKey();
string privateKey = rsa.ExportPrivateKey();

string plainText = "Encrypting and decrypting should be easy!";
            plainText = text;
//  Start with a new RSA object to demonstrate that all we
//  need are the keys previously exported:
Chilkat.Rsa rsaEncryptor = new Chilkat.Rsa();

//  Encrypted output is always binary.  In this case, we want
//  to encode the encrypted bytes in a printable string.
//  Our choices are "hex", "base64", "url", "quoted-printable".
rsaEncryptor.EncodingMode = "hex";

//  We'll encrypt with the public key and decrypt with the private
//  key.  It's also possible to do the reverse.
success = rsaEncryptor.ImportPublicKey(publicKey);

bool usePrivateKey = false;
string encryptedStr = rsaEncryptor.EncryptStringENC(plainText,usePrivateKey);
//Console.WriteLine(encryptedStr);

//  Now decrypt:
Chilkat.Rsa rsaDecryptor = new Chilkat.Rsa();

rsaDecryptor.EncodingMode = "hex";
success = rsaDecryptor.ImportPrivateKey(privateKey);

usePrivateKey = true;
string decryptedStr = rsaDecryptor.DecryptStringENC(encryptedStr,usePrivateKey);

//Console.WriteLine(decryptedStr);

        }

        public static void performDeffieHelman(string text)
        {
            //  Create two separate instances of the DH object.
            Chilkat.Dh dhBob = new Chilkat.Dh();
            Chilkat.Dh dhAlice = new Chilkat.Dh();

            //  The DH algorithm begins with a large prime, P, and a generator, G.
            //  These don't have to be secret, and they may be transmitted over an insecure channel.
            //  The generator is a small integer and typically has the value 2 or 5.

            //  The Chilkat DH component provides the ability to use known
            //  "safe" primes, as well as a method to generate new safe primes.

            //  This example will use a known safe prime.  Generating
            //  new safe primes is a time-consuming CPU intensive task
            //  and is normally done offline.

            //  Bob will choose to use the 2nd of our 8 pre-chosen safe primes.
            //  It is the Prime for the 2nd Oakley Group (RFC 2409) --
            //  1024-bit MODP Group.  Generator is 2.
            //  The prime is: 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }
            dhBob.UseKnownPrime(2);

            //  The computed shared secret will be equal to the size of the prime (in bits).
            //  In this case the prime is 1024 bits, so the shared secret will be 128 bytes (128 * 8 = 1024).
            //  However, the result is returned as an SSH1-encoded bignum in hex string format.
            //  The SSH1-encoding prepends a 2-byte count, so the result is going  to be 2 bytes
            //  longer: 130 bytes.  This results in a hex string that is 260 characters long (two chars
            //  per byte for the hex encoding).

            string p;
            int g;
            //  Bob will now send P and G to Alice.
            p = dhBob.P;
            g = dhBob.G;

            //  Alice calls SetPG to set P and G.  SetPG checks
            //  the values to make sure it's a safe prime and will
            //  return false if not.
            

            //  Each side begins by generating an "E"
            //  value.  The CreateE method has one argument: numBits.
            //  It should be set to twice the size of the number of bits
            //  in the session key.

            //  Let's say we want to generate a 128-bit session key
            //  for AES encryption.  The shared secret generated by the Diffie-Hellman
            //  algorithm will be longer, so we'll hash the result to arrive at the
            //  desired session key length.  However, the length of the session
            //  key we'll utlimately produce determines the value that should be
            //  passed to the CreateE method.

            //  In this case, we'll be creating a 128-bit session key, so pass 256 to CreateE.
            //  This setting is for security purposes only -- the value
            //  passed to CreateE does not change the length of the shared secret
            //  that is produced by Diffie-Hellman.
            //  Also, there is no need to pass in a value larger
            //  than 2 times the expected session key length.  It suffices to
            //  pass exactly 2 times the session key length.

            //  Bob generates a random E (which has the mathematical
            //  properties required for DH).
            string eBob;
            eBob = dhBob.CreateE(256);

            //  Alice does the same:
            string eAlice;
            eAlice = dhAlice.CreateE(256);

            //  The "E" values are sent over the insecure channel.
            //  Bob sends his "E" to Alice, and Alice sends her "E" to Bob.

            //  Each side computes the shared secret by calling FindK.
            //  "K" is the shared-secret.

            string kBob;
            string kAlice;

            //  Bob computes the shared secret from Alice's "E":
            kBob = dhBob.FindK(eAlice);

            //  Alice computes the shared secret from Bob's "E":
            kAlice = dhAlice.FindK(eBob);

            //  Amazingly, kBob and kAlice are identical and the expected
            //  length (260 characters).  The strings contain the hex encoded bytes of
            //  our shared secret:
           // Console.WriteLine("Bob's shared secret:");
           // Console.WriteLine(kBob);
           // Console.WriteLine("Alice's shared secret (should be equal to Bob's)");
           // Console.WriteLine(kAlice);

            //  To arrive at a 128-bit session key for AES encryption, Bob and Alice should
            //  both transform the raw shared secret using a hash algorithm that produces
            //  the size of session key desired.   MD5 produces a 16-byte (128-bit) result, so
            //  this is a good choice for 128-bit AES.

            //  Here's how you would use Chilkat Crypt (a separate Chilkat component) to
            //  produce the session key:
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();
           

            crypt.EncodingMode = "hex";
            crypt.HashAlgorithm = "md5";

            string sessionKey;
            sessionKey = crypt.HashStringENC(kBob);

           // Console.WriteLine("128-bit Session Key:");
           // Console.WriteLine(sessionKey);

            //  Encrypt something...
            crypt.CryptAlgorithm = "aes";
            crypt.KeyLength = 128;
            crypt.CipherMode = "cbc";

            //  Use an IV that is the MD5 hash of the session key...
            string iv;
            iv = crypt.HashStringENC(sessionKey);

            //  AES uses a 16-byte IV:
            //Console.WriteLine("Initialization Vector:");
            //Console.WriteLine(iv);

            crypt.SetEncodedKey(sessionKey, "hex");
            crypt.SetEncodedIV(iv, "hex");

            //  Encrypt some text:
            string cipherText64;

            crypt.EncodingMode = "base64";
            cipherText64 = crypt.EncryptStringENC(text);
            //Console.WriteLine(cipherText64);

            string plainText;
            plainText = crypt.DecryptStringENC(cipherText64);

            //Console.WriteLine(plainText);

        }

        public static void performTwoFish(string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

            //  Set the encryption algorithm = "twofish"
            crypt.CryptAlgorithm = "twofish";

            //  CipherMode may be "ecb" or "cbc"
            crypt.CipherMode = "cbc";

            //  KeyLength may be 128, 192, 256
            crypt.KeyLength = 256;

            //  The padding scheme determines the contents of the bytes
            //  that are added to pad the result to a multiple of the
            //  encryption algorithm's block size.  Twofish has a block
            //  size of 16 bytes, so encrypted output is always
            //  a multiple of 16.
            crypt.PaddingScheme = 0;

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  It may be "hex", "url", "base64", or "quoted-printable".
            crypt.EncodingMode = "hex";

            //  An initialization vector is required if using CBC mode.
            //  ECB mode does not use an IV.
            //  The length of the IV is equal to the algorithm's block size.
            //  It is NOT equal to the length of the key.
            string ivHex = "000102030405060708090A0B0C0D0E0F";
            crypt.SetEncodedIV(ivHex, "hex");

            //  The secret key must equal the size of the key.  For
            //  256-bit encryption, the binary secret key is 32 bytes.
            //  For 128-bit encryption, the binary secret key is 16 bytes.
            string keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
            crypt.SetEncodedKey(keyHex, "hex");

            //  Encrypt a string...
            //  The input string is 44 ANSI characters (i.e. 44 bytes), so
            //  the output should be 48 bytes (a multiple of 16).
            //  Because the output is a hex string, it should
            //  be 96 characters long (2 chars per byte).
            string encStr = crypt.EncryptStringENC(text);
          //  Console.WriteLine(encStr);

            //  Now decrypt:
            string decStr = crypt.DecryptStringENC(encStr);
          //  Console.WriteLine(decStr);
        }


        public static void performBlowfish2(string text)
        {
                Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

                //  Attention: use "blowfish2" for the algorithm name:
                crypt.CryptAlgorithm = "blowfish2";

                //  CipherMode may be "ecb", "cbc", or "cfb"
                crypt.CipherMode = "cbc";

                //  KeyLength (in bits) may be a number between 32 and 448.
                //  128-bits is usually sufficient.  The KeyLength must be a
                //  multiple of 8.
                crypt.KeyLength = 128;

                //  The padding scheme determines the contents of the bytes
                //  that are added to pad the result to a multiple of the
                //  encryption algorithm's block size.  Blowfish has a block
                //  size of 8 bytes, so encrypted output is always
                //  a multiple of 8.
                crypt.PaddingScheme = 0;

                //  EncodingMode specifies the encoding of the output for
                //  encryption, and the input for decryption.
                //  It may be "hex", "url", "base64", or "quoted-printable".
                crypt.EncodingMode = "hex";

                //  An initialization vector is required if using CBC or CFB modes.
                //  ECB mode does not use an IV.
                //  The length of the IV is equal to the algorithm's block size.
                //  It is NOT equal to the length of the key.
                string ivHex = "0001020304050607";
                crypt.SetEncodedIV(ivHex, "hex");

                //  The secret key must equal the size of the key.  For
                //  256-bit encryption, the binary secret key is 32 bytes.
                //  For 128-bit encryption, the binary secret key is 16 bytes.
                string keyHex = "000102030405060708090A0B0C0D0E0F";
                crypt.SetEncodedKey(keyHex, "hex");

                //  Encrypt a string...
                //  The input string is 44 ANSI characters (i.e. 44 bytes), so
                //  the output should be 48 bytes (a multiple of 8).
                //  Because the output is a hex string, it should
                //  be 96 characters long (2 chars per byte).
                string encStr = crypt.EncryptStringENC(text);
                //Console.WriteLine(encStr);

                //  Now decrypt:
                string decStr = crypt.DecryptStringENC(encStr);
                //Console.WriteLine(decStr);
         }
        


    public static void performARC4(string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

            //  Set the encryption algorithm = "arc4"
            crypt.CryptAlgorithm = "arc4";

            //  KeyLength may range from 1 byte to 256 bytes.
            //  (i.e. 8 bits to 2048 bits)
            //  ARC4 key sizes are typically in the range of
            //  40 to 128 bits.
            //  The KeyLength property is specified in bits:
            crypt.KeyLength = 128;

            //  Note: The PaddingScheme and CipherMode properties
            //  do not apply w/ ARC4.  ARC4 does not encrypt in blocks --
            //  it is a streaming encryption algorithm. The number of output bytes
            //  is exactly equal to the number of input bytes.

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  It may be "hex", "url", "base64", or "quoted-printable".
            crypt.EncodingMode = "hex";

            //  Note: ARC4 does not utilize initialization vectors.  IV's only
            //  apply to block encryption algorithms.

            //  The secret key must equal the size of the key.
            //  For 128-bit encryption, the binary secret key is 16 bytes.
            string keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
            crypt.SetEncodedKey(keyHex, "hex");

            //  Encrypt a string...
            //  The output length is exactly equal to the input.  In this
            //  example, the input string is 44 chars (ANSI bytes) so the
            //  output is 44 bytes -- and when hex encoded results in an
            //  88-char string (2 chars per byte for the hex encoding).
            string encStr = crypt.EncryptStringENC(text);
            //Console.WriteLine(encStr);

            //  Now decrypt:
            string decStr = crypt.DecryptStringENC(encStr);
            //Console.WriteLine(decStr);

        }

        public static void performAESGCM(string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

            bool success = crypt.UnlockComponent("Anything for 30-day trial");
            if (success != true)
            {
                Console.WriteLine(crypt.LastErrorText);
                return;
            }

            //  Set the encryption algorithm to "AES"
            crypt.CryptAlgorithm = "aes";

            //  Indicate that the Galois/Counter Mode (GCM) should be used:
            crypt.CipherMode = "gcm";

            //  KeyLength may be 128, 192, 256
            crypt.KeyLength = 128;

            //  This is the 128-bit AES secret key (in hex format)
            string K = "feffe9928665731c6d6a8f9467308308";

            //  This is the 16-byte initialization vector:
            string IV = "cafebabefacedbaddecaf888";

            //  This is the additional data to be used as input to the GCM AEAD algorithm,
            //  but is not included in the output.  It plays a role in the computation of the
            //  resulting authenticated tag.
            string AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

            //  The plain-text bytes (in hex format) to be encrypted.
            string PT = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

            PT = text;

            //  The expected cipher text (in hex format)
            string CT = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";

            //  The expected authenticated tag given the above inputs.
            string T = "5bc94fbc3221a5db94fae95ae7121a47";

            //  Note: The above data are the values for test vector #4 from
            //  the PDF document at: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  It may be "hex", "url", "base64", or "quoted-printable".
            crypt.EncodingMode = "hex";

            //  Set the secret key and IV
            crypt.SetEncodedIV(IV, "hex");
            crypt.SetEncodedKey(K, "hex");

            //  Set the additional authenticated data (AAD)
            success = crypt.SetEncodedAad(AAD, "hex");

            //  For the purpose of duplicating the test vectors, we are using the EncryptEncoded method.
            //  This method decodes the input string according to the encoding specified by the EncodingMode
            //  property, which in this case is "hex".  The decoded bytes are encrypted using the mode specified
            //  by the CipherMode property.  The resulting
            //  encrypted bytes are encoded (again using the encoding mode specified by EncodingMode),
            //  and the result is returned.
            //  <b>Note:</b> The CipherMode property sets the block mode of operation (gcm, cfb, cbc, ofb, ecb, etc.)
            //  for any of the Chilkat encryption/decryption methods (such as EncryptBytes, EncryptString,
            //  CkEncryptFile, etc.)   Just because GCM mode is demonstrated with EncryptEncoded/DecryptEncoded,
            //  does not imply that GCM mode is specific to only these methods.
            string ctResult = crypt.EncryptEncoded(PT);
            if (crypt.LastMethodSuccess != true)
            {
             //   Console.WriteLine(crypt.LastErrorText);
                return;
            }

            //  Examine the result.  It should be the same (case insensitive) as our expected result:
           // Console.WriteLine("computed result: " + ctResult);
           // Console.WriteLine("expected result: " + CT);

            //  Examine the authenticated tag. It should be the same (case insensitive) as our expected authenticated tag:
            string tResult = crypt.GetEncodedAuthTag("hex");
            //Console.WriteLine("computed authTag: " + tResult);
            //Console.WriteLine("expected authTag: " + T);

            //  -------------------------------------------------------------------------------------
            //  Now let's GCM decrypt...
            //  -------------------------------------------------------------------------------------

            //  Before GCM decrypting, we must set the authenticated tag to the value that is expected.
            //  The decryption will fail if the resulting authenticated tag is not equal (case insensitive) to
            //  the expected result.
            //  Note: The return value of SetEncodedAuthTag indicates whether the string passed was a valid
            //  representation of the encoding specified in the 2nd arg.
            success = crypt.SetEncodedAuthTag(T, "hex");

            //  All of our properties (IV, secret key, cipher mode, and AAD) are already set from the code above...

            //  So let's decrypt CT to and check to see if we get PT.
            string ptResult = crypt.DecryptEncoded(CT);
            if (crypt.LastMethodSuccess != true)
            {
                //  Failed.  The resultant authenticated tag did not equal the expected authentication tag.
               // Console.WriteLine(crypt.LastErrorText);
                return;
            }

            //  Examine the decrypted result.  It should be the same as our expected plaintext (case insensitive)
            //Console.WriteLine("plaintext decrypted: " + ptResult);
            //Console.WriteLine("plaintext expected:  " + PT);

            //  Let's intentionally set the expected authenticated tag to an incorrect value.
            //  The decrypt operation should fail:
            string tInvalid = "ffaabbbc3221a5db94fae95ae7121a47";

            success = crypt.SetEncodedAuthTag(tInvalid, "hex");

            ptResult = crypt.DecryptEncoded(CT);
            if (crypt.LastMethodSuccess != true)
            {
                //  Failed.  The resultant authenticated tag did not equal the expected authentication tag.
               // Console.WriteLine(crypt.LastErrorText);
            }
        }

        public static void perform3DES(string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

            bool success = crypt.UnlockComponent("Anything for 30-day trial");
            if (success != true)
            {
                Console.WriteLine(crypt.LastErrorText);
                return;
            }

            //  Specify 3DES for the encryption algorithm:
            crypt.CryptAlgorithm = "3des";

            //  CipherMode may be "ecb" or "cbc"
            crypt.CipherMode = "cbc";

            //  KeyLength must be 192.  3DES is technically 168-bits;
            //  the most-significant bit of each key byte is a parity bit,
            //  so we must indicate a KeyLength of 192, which includes
            //  the parity bits.
            crypt.KeyLength = 192;

            //  The padding scheme determines the contents of the bytes
            //  that are added to pad the result to a multiple of the
            //  encryption algorithm's block size.  3DES has a block
            //  size of 8 bytes, so encrypted output is always
            //  a multiple of 8.
            crypt.PaddingScheme = 0;

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  It may be "hex", "url", "base64", or "quoted-printable".
            crypt.EncodingMode = "hex";

            //  An initialization vector is required if using CBC or CFB modes.
            //  ECB mode does not use an IV.
            //  The length of the IV is equal to the algorithm's block size.
            //  It is NOT equal to the length of the key.
            string ivHex = "0001020304050607";
            crypt.SetEncodedIV(ivHex, "hex");

            //  The secret key must equal the size of the key.  For
            //  3DES, the key must be 24 bytes (i.e. 192-bits).
            string keyHex = "000102030405060708090A0B0C0D0E0F0001020304050607";
            crypt.SetEncodedKey(keyHex, "hex");

           
            string encStr = crypt.EncryptStringENC(text);
            //Console.WriteLine(encStr);

            //  Now decrypt:
            string decStr = crypt.DecryptStringENC(encStr);
           // Console.WriteLine(decStr);
        }

        public static void performPoly1305MAC(string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

            bool success = crypt.UnlockComponent("Anything for 30-day trial");
            if (success != true)
            {
                Console.WriteLine(crypt.LastErrorText);
                return;
            }

            //  Set the MAC algorithm to poly1305
            crypt.MacAlgorithm = "poly1305";

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  Valid modes are (case insensitive) "Base64", "modBase64", "Base32", "Base58", "UU",
            //  "QP" (for quoted-printable), "URL" (for url-encoding), "Hex",
            //  "Q", "B", "url_oauth", "url_rfc1738", "url_rfc2396", and "url_rfc3986".
            crypt.EncodingMode = "hex";

            //  Poly1305 always uses a 32-byte (256-bit) MAC key.
            string keyHex = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
            success = crypt.SetMacKeyEncoded(keyHex, "hex");

            string plainText = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";

            //  The computed tag should match the Tag shown below.
            //  (Note: hexidecimal encoding is case insensitive.)
            string encTag = crypt.MacStringENC(text);
            //Console.WriteLine(encTag);
        }      

        public static void performChaChaEncryption( string text)
        {
            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();
            //  Set the encryption algorithm to chacha20
            //  chacha20 is a stream cipher, and therefore no cipher mode applies.

            //  Set the encryption algorithm to chacha20
            //  chacha20 is a stream cipher, and therefore no cipher mode applies.
            crypt.CryptAlgorithm = "chacha20";

            //  The key length for chacha20 is always 256-bits.
            crypt.KeyLength = 256;

            //  Note: "padding" only applies to block encryption algorithmns.
            //  Since chacha20 is a stream cipher, there is no padding and the output
            //  number of bytes is exactly equal to the input.

            //  EncodingMode specifies the encoding of the output for
            //  encryption, and the input for decryption.
            //  Valid modes are (case insensitive) "Base64", "modBase64", "Base32", "Base58", "UU",
            //  "QP" (for quoted-printable), "URL" (for url-encoding), "Hex",
            //  "Q", "B", "url_oauth", "url_rfc1738", "url_rfc2396", and "url_rfc3986".
            crypt.EncodingMode = "hex";

            //  The inputs to ChaCha20 encryption, specified by RFC 7539, are:
            //  1) A 256-bit secret key.
            //  2) A 96-bit nonce.
            //  3) A 32-bit initial count.
            //  The IV property is used to specify the chacha20 nonce.
            //  For a 96-bit nonce, the IV should be 12 bytes in length.
            // 
            //  Note: Some implementations of chacha20, such as that used internally by SSH,
            //  use a 64-bit nonce and 64-bit count.  To do chacha20 encryption in this way,
            //  simply provide 8 bytes for the IV instead of 12 bytes.  Chilkat will then automatically
            //  use 8 bytes (64-bits) for the count.

            //  This example duplicates Test Vector #3 (for ChaCha20 encryption) from RFC 7539.
            string ivHex = "000000000000000000000002";
            crypt.SetEncodedIV(ivHex, "hex");

            crypt.InitialCount = 42;

            string keyHex = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
            crypt.SetEncodedKey(keyHex, "hex");

            // string plainText = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";


            string encStr = crypt.EncryptStringENC(text);
            //Console.WriteLine(encStr);
            //Console.WriteLine("I am wor");

            //  Now decrypt:
            string decStr = crypt.DecryptStringENC(encStr);
            //Console.WriteLine(decStr);
        }
    }
}
