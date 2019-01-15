using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;

namespace EncryptionMethods
{
    class Program
    {
        static void Main(string[] args)
        {

            var stopwatch = new Stopwatch();

            Console.WriteLine("Enter a text to encrypt");
            string text = Console.ReadLine();
            Console.WriteLine(text);
            AES_Class AES_Object = new AES_Class();

            stopwatch.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES128(text);
            }
            stopwatch.Stop();
            var elapsed = stopwatch.Elapsed.Milliseconds;

            var stopwatch2 = new Stopwatch();
            stopwatch2.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES192(text);
            }
            stopwatch2.Stop();
            var elapsed1 = stopwatch2.Elapsed.Milliseconds;



            var stopwatch3 = new Stopwatch();
            stopwatch3.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES256(text);
            }
            stopwatch3.Stop();
            var elapsed2 = stopwatch3.Elapsed.Milliseconds;

            var stopwatch4 = new Stopwatch();
            stopwatch4.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAESCTS(text);
            }
            stopwatch4.Stop();
            var elapsedCTS = stopwatch4.Elapsed.Milliseconds;

            var stopwatch5 = new Stopwatch();
            stopwatch5.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES256CBC(text);
            }
            stopwatch5.Stop();
            var elapsedCBC = stopwatch5.Elapsed.Milliseconds;

            var stopwatch6 = new Stopwatch();
            stopwatch6.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES256ECB(text);
            }
            stopwatch6.Stop();
            var elapsedECB = stopwatch6.Elapsed.Milliseconds;


            var stopwatch7 = new Stopwatch();
            stopwatch7.Start();
            for (int r = 0; r <= 100; r++)
            {
                AES_Object.performAES256OFB(text);
            }
            stopwatch7.Stop();
            var elapsedOFB = stopwatch7.Elapsed.Milliseconds;


            var stopwatch8 = new Stopwatch();
            stopwatch8.Start();
            for (int r = 0; r <= 100; r++)
            {
                Alice.performEllipticCurveDH(text);
            }
            stopwatch8.Stop();
            var elapsedECDH = stopwatch8.Elapsed.Milliseconds;

            var stopwatch9 = new Stopwatch();
            stopwatch9.Start();
            for (int r = 0; r <= 100; r++)
            {
                RSA_Class.performRSAMethod(text);
            }
            stopwatch9.Stop();
            var elapsedRSA = stopwatch9.Elapsed.Milliseconds;

            var stopwatch10 = new Stopwatch();
            stopwatch10.Start();
            DES_Class DES_Object = new DES_Class();
            for (int r = 0; r <= 100; r++)
            {
                DES_Object.performDES(text);
            }
            stopwatch10.Stop();
            var elapsedDES = stopwatch10.Elapsed.Milliseconds;


            var stopwatch11 = new Stopwatch();
            stopwatch11.Start();
            //for (int r = 0; r <= 100; r++)
            //{
            //    Triple_DES.performTripleDES_FILES(text);
            //}
            stopwatch11.Stop();
            var elapsed3DES_FILES = stopwatch11.Elapsed.Milliseconds;

            var stopwatch12 = new Stopwatch();
            stopwatch12.Start();
            for (int r = 0; r <= 100; r++)
            {
                Triple_DES.performTripleDES_MEMORY(text);
            }
            stopwatch12.Stop();
            var elapsed3DES_MEMORY = stopwatch12.Elapsed.Milliseconds;

            var stopwatch13 = new Stopwatch();
            stopwatch13.Start();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performChaChaEncryption(text);
            }
            stopwatch13.Stop();
            var elapsedChilkatChacha = stopwatch13.Elapsed.Milliseconds;

            stopwatch.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performPoly1305MAC(text);
            }
            stopwatch.Stop();
            var elapsedChilkatPoly1305 = stopwatch.Elapsed.Milliseconds;

            stopwatch2.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.perform3DES(text);
            }
            stopwatch2.Stop();
            var elapsedChilkat3DES = stopwatch2.Elapsed.Milliseconds;

            stopwatch3.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performAESGCM(text);
            }
            stopwatch3.Stop();
            var elapsedChilkatAESGSM = stopwatch3.Elapsed.Milliseconds;

            stopwatch4.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performARC4(text);
            }
            stopwatch4.Stop();

            var elapsedChilkatARC4 = stopwatch4.Elapsed.Milliseconds;

            stopwatch5.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performBlowfish2(text);
            }
            stopwatch5.Stop();

            var elapsedChilkatBlowfish = stopwatch5.Elapsed.Milliseconds;

            stopwatch6.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performTwoFish(text);
            }
            stopwatch6.Stop();

            var elapsedChilkatTwoFish = stopwatch6.Elapsed.Milliseconds;

            stopwatch7.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performDeffieHelman(text);
            }
            stopwatch7.Stop();

            var elapsedChilkatDeffieHelman = stopwatch7.Elapsed.Milliseconds;


            stopwatch8.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performRSA(text);
            }
            stopwatch8.Stop();

            var elapsedChilkatRSA = stopwatch8.Elapsed.Milliseconds;

            stopwatch9.Restart();
            for (int r = 0; r <= 100; r++)
            {
                ChilkatLibraryMethods.performRSA(text);
            }
            stopwatch9.Stop();

            var elapsedChilkatECCSharedSECret = stopwatch9.Elapsed.Milliseconds;




            Console.WriteLine("AES 128 bit took {0} milliseconds", elapsed);
            Console.WriteLine("AES 192 bit took {0} milliseconds", elapsed1);
            Console.WriteLine("AES 256 bit took {0} milliseconds", elapsed2);
            Console.WriteLine("AES CFB mode took {0} milliseconds", elapsedCTS);
            Console.WriteLine("AES CBC mode took {0} milliseconds", elapsedCBC);
            Console.WriteLine("AES ECB mode took {0} milliseconds", elapsedECB);
            Console.WriteLine("AES OFB mode took {0} milliseconds", elapsedOFB);
            Console.WriteLine("Elleptic Curve Deffi Hellman took {0} milliseconds", elapsedECDH);
            Console.WriteLine("RSA Method took {0} milliseconds", elapsedRSA);
            Console.WriteLine("DES Method took {0} milliseconds", elapsedDES);
            //Console.WriteLine("Triple DES to files took {0} milliseconds", elapsed3DES_FILES);
            Console.WriteLine("Triple DES to memory took {0} milliseconds", elapsed3DES_MEMORY);
            Console.WriteLine("Chilkat Chacha20 {0} milliseconds", elapsedChilkatChacha);
            Console.WriteLine("Chilkat poly1305 {0} milliseconds", elapsedChilkatPoly1305);
            Console.WriteLine("Chilkat 3-DES {0} milliseconds", elapsedChilkat3DES);
            Console.WriteLine("Chilkat AES GCM {0} milliseconds", elapsedChilkatAESGSM);
            Console.WriteLine("Chilkat ARC4 took {0} milliseconds", elapsedChilkatARC4);
            Console.WriteLine("Chilkat BlowFish took {0} milliseconds", elapsedChilkatBlowfish);
            Console.WriteLine("Chilkat TwoFish took {0} milliseconds", elapsedChilkatTwoFish);
            Console.WriteLine("Chilkat Deffie Hellman took {0} milliseconds", elapsedChilkatDeffieHelman);
            Console.WriteLine("Chilkat RSA took {0} milliseconds", elapsedChilkatRSA);
            Console.WriteLine("Chilkat ECC Shared Secret took {0} milliseconds", elapsedChilkatECCSharedSECret);
            
            Console.ReadKey();
        }
    }
}
