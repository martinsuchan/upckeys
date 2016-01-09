using System;

namespace UpcKeysConsole
{
    class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                Banner();

                if (args.Length != 2)
                {
                    Usage();
                    return;
                }

                string essid = args[0];
                if (essid.Length != 10 || !essid.StartsWith("UPC"))
                {
                    Usage();
                    return;
                }

                string modestr = args[1];
                Mode mode;
                if (modestr == "24") mode = Mode.G24;
                else if (modestr == "5") mode = Mode.G5;
                else
                {
                    Usage();
                    return;
                }

                int count = 0;
                foreach (Tuple<string, string> pair in UpcRecover.GetCandidates(essid, mode))
                {
                    count++;
                    Console.WriteLine("  -> WPA2 phrase for '{0}' = '{1}'", pair.Item1, pair.Item2);
                }

                Console.WriteLine("\n  => found {0} possible WPA2 phrases, enjoy!\n", count);
                Console.ReadKey();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static void Banner()
        {
            Console.WriteLine(
                " ================================================================\n" +
                "  upc_keys // WPA2 passphrase recovery tool for UPC%%07d devices \n" +
                " ================================================================\n" +
                "  by blasty <peter@haxx.in>\n");
        }

        private static void Usage()
        {
            Console.WriteLine("  Usage: UpcKeysConsole <ESSID> <band>\n");
            Console.WriteLine("   - ESSID should be in 'UPCxxxxxxx' format\n");
            Console.WriteLine("   - band should be either '24' for 2.4GHz or '5' for 5GHz\n");
        }
    }
}