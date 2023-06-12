# INZDetector
This is a basic detector for the INZ Stealer malware. It checks for the presence of specific strings in the executable's code, strings heap, and US heap.

## Usage

To use the detector, run the `INZDetector.exe` executable and provide the path to the executable you want to scan as a command-line argument:

```
INZDetector.exe path/to/executable.exe
```

Alternatively, you can run the executable without any arguments and enter the path when prompted.

## Detection Method

The detector checks for the presence of the following strings:

- "INZStealer 2.0"
- "/INZ/Passwords.txt"
- "INZ"
- "SELECT password_value"
- "INZ\\Login Data"
- "Local State"

It checks for these strings in the following locations:

- The code of the executable, by searching for the `ldstr` instruction that loads the string onto the stack.
- The strings heap of the executable, by iterating through the strings in the `#Strings` stream of the metadata and checking if any of them match the flagged strings.
- The US heap of the executable, by iterating through the strings in the `#US` stream of the metadata and checking if any of them match the flagged strings.

If any of the flagged strings are found in any of these locations, the executable is flagged as a potential INZ Stealer.

## Dependencies

This detector uses the following dependencies:

- dnlib 3.6.0

## License

This code is released under the MIT License. See `LICENSE.txt` for details.

## Credits

This detector was created by [Yeetret].
