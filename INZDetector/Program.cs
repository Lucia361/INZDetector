using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;

namespace INZDetector
{
    internal class Program
    {
        // Set of strings that are flagged as indicators of INZ Stealer malware
        private static HashSet<string> flaggedStrings = new HashSet<string>
        {
            "INZStealer 2.0",
            "/INZ/Passwords.txt",
            "INZ",
            "SELECT password_value",
            "INZ\\Login Data",
            "Local State",
        };

        private static void Main(string[] args)
        {
            // Set console title
            Console.Title = "INZ Stealer Detector || Basic || Yeetret";

            // Get path to executable from command-line arguments or user input
            string fp;
            try
            {
                fp = args[0];
            }
            catch
            {
                Console.WriteLine("Enter your path:");
                fp = Console.ReadLine();
            }

            // Load the executable as a module
            ModuleDefMD md = ModuleDefMD.Load(fp);

            // Check if the executable is detected as an INZ Stealer
            if (Detect(md) || DetectStringsHeap(md) || DetectUSHeap(md))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Executable is detected as a INZ stealer!");
                Console.ReadKey();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Executable is not detected as a INZ stealer");
                Console.ReadKey();
            }
        }

        // Detect INZ Stealer indicators in the code of the executable
        private static bool Detect(ModuleDefMD mod)
        {
            // Use LINQ to search for instructions that load strings that match the flagged strings
            return (from types in mod.GetTypes().Where(x => x.HasMethods)
                    from methods in types.Methods.Where(x => x.HasBody && x.Body.HasInstructions)
                    from instr in methods.Body.Instructions
                    where instr.OpCode.Code == Code.Ldstr
                    select instr)
                .Any(instr => flaggedStrings.Contains(instr.Operand));
        }

        // Detect INZ Stealer indicators in the strings heap of the executable
        private static bool DetectStringsHeap(ModuleDefMD mod)
        {
            // Get the strings stream from the metadata of the module
            StringsStream stringsStream = mod.Metadata.StringsStream;

            // Get the length of the strings stream
            uint stringsStreamLength = stringsStream.StreamLength;

            // Initialize offset and detection flag
            uint offset = 1;
            bool d = false;

            // Loop through the strings in the strings stream
            while (offset < stringsStreamLength)
            {
                // Read the current string from the strings stream
                string currentString = stringsStream.ReadNoNull(offset);

                // Increment the offset by the length of the current string plus one (for the null terminator)
                offset += (uint)currentString.Length + 1;

                // Check if the current string matches any of the flagged strings
                if (flaggedStrings.Contains(currentString))
                    d = true;
            }

            // Return the detection flag
            return d;
        }

        // Detect INZ Stealer indicators in the US heap of the executable
        private static bool DetectUSHeap(ModuleDefMD mod)
        {
            // Get the US stream from the metadata of the module
            USStream stringsStream = mod.Metadata.USStream;

            // Get the length of the US stream
            uint stringsStreamLength = stringsStream.StreamLength;

            // Initialize offset and detection flag
            uint offset = 1;
            bool d = false;

            // Loop through the strings in the US stream
            while (offset < stringsStreamLength)
            {
                // Read the current string from the US stream
                string currentString = stringsStream.ReadNoNull(offset);

                // Increment the offset by the length of the current string plus one (for the null terminator)
                offset += (uint)currentString.Length + 1;

                // Check if the current string matches any of the flagged strings
                if (flaggedStrings.Contains(currentString))
                    d = true;
            }

            // Return the detection flag
            return d;
        }
    }
}
