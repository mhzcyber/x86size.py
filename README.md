[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/badge/release-v1.0-green.svg)](https://github.com/mhzcyber/YOUR_REPO/releases)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=social&logo=linkedin)](https://www.linkedin.com/in/mhzcyber/)

# x86size.py
Calculate x86/x86-64 instruction and ROP gadget sizes using Keystone assembler

![x86size_banner](https://github.com/mhzcyber/x86size.py/blob/main/attachements/x86size_banner.png)

```
 ./x86size.py --help
usage: x86size.py [-h] [-f FILE] [-m {32,64}] [-b] [-v] [-g] [--no-color] [--no-banner] [instruction]

Calculate x86/x86-64 instruction and ROP gadget sizes using Keystone assembler

positional arguments:
  instruction           Single instruction or gadget to analyze (if -f is not used)

options:
  -h, --help            Show this help message and exit
  -f FILE, --file FILE  File containing instructions/gadgets (one per line). Use '-' for stdin
  -m {32,64}, --mode {32,64}
                        Assembly mode (default: 32)
  -b, --both            Show results for both 32-bit and 64-bit modes
  -v, --verbose         Show detailed breakdown for each instruction in gadgets
  -g, --gadgets-only    Only process lines that contain ROP gadgets (have semicolons)
  --no-color            Disable colored output
  --no-banner           Don't display the banner

Examples:
  # Single instruction (32-bit mode by default)
  x86size.py "mov eax, 1"
  
  # Single ROP gadget
  x86size.py "pop eax ; ret"
  
  # ROP gadget in 64-bit mode
  x86size.py -m 64 "pop rax ; pop rbx ; ret"
  
  # Process a file of instructions/gadgets
  x86size.py -f gadgets.txt
  
  # Process a file with verbose output
  x86size.py -f gadgets.txt -v
  
  # Process stdin
  echo "pop eax ; ret" | x86size.py -f -
  
File format:
  • One instruction or gadget per line
  • Gadgets are multiple instructions separated by semicolons
  • Empty lines are ignored
  • Lines starting with # are treated as comments
  
Example file:
  # Single instructions
  mov eax, 1
  jmp esp
  
  # ROP gadgets
  pop eax ; ret
  pop ebx ; pop ecx ; ret
  xchg eax, esp ; ret

Tips:
  • Use -v for detailed gadget breakdown
  • Use -b to compare 32-bit vs 64-bit encodings
  • Use -g to filter only ROP gadgets from mixed input
  • Pipe gadgets from ROPgadget or other tools via stdin
```

## Usage

https://github.com/user-attachments/assets/118d0528-9fc6-4456-ae43-39e3e6990019

