#!/usr/bin/env python3
import argparse
import sys
import os
import keystone
from keystone import KsError  # Import the correct error class

# Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

BANNER = f"""{Colors.OKCYAN}
                .;;;;;,.                
             ...cdddddo;...             
            ,loodddddddoooc'            
         .,;cdddddddddddddoc;'.         
         ,odlccloddddddlcccodc.         
      .;:cdo,. .:dddddo,. .cdoc:,.      
      ;ddddo;...:dddddo;...cddddl.      
      ;dddddollodddddddoooooddddl.      
      .',,,;lddoc,,,,,;lddoc,'''.       
           .;ddo,     .:ddl'            
         .;;;,,,;:;;;;:;,,,;;,.         
     ....;cc,...;cccccc,..';c:'...      
     ;ooo;..;ool,.    .:ool,..:ooc.     
     ,ccc'  'cc:.      ,lc:. .,cc;.     
                                        
                                        
                                        

{Colors.BOLD}{Colors.OKBLUE} #     # #     # #######  #####  #     # ######  ####### ######  
 ##   ## #     #      #  #     #  #   #  #     # #       #     # 
 # # # # #     #     #   #         # #   #     # #       #     # 
 #  #  # #######    #    #          #    ######  #####   ######  
 #     # #     #   #     #          #    #     # #       #   #   
 #     # #     #  #      #     #    #    #     # #       #    #  
 #     # #     # #######  #####     #    ######  ####### #     # {Colors.ENDC}

{Colors.WARNING}               [!] x86/x64 Instruction Size Calculator{Colors.ENDC}
{Colors.HEADER}               [!] Analyze instruction & ROP gadget sizes{Colors.ENDC}
"""

def get_instruction_details(instruction, arch, mode):
    """
    Gets the size and encoding of a single assembly instruction
    using the Keystone assembler.
    """
    try:
        ks = keystone.Ks(arch, mode)
        # Assemble the instruction into machine code
        encoding, _ = ks.asm(instruction)
        
        # Convert to hex string for display
        hex_encoding = ' '.join(f'{b:02x}' for b in encoding)
        
        return len(encoding), hex_encoding
    except KsError as e:
        # Handle Keystone errors (like missing CPU features, invalid instructions)
        error_msg = str(e)
        if "KS_ERR_ASM_MISSINGFEATURE" in error_msg:
            return None, "Not supported in this mode"
        elif "KS_ERR_ASM_INVALIDOPERAND" in error_msg:
            return None, "Invalid operand"
        else:
            return None, error_msg
    except Exception as e:
        # Handle any other unexpected errors
        return None, f"Unexpected error: {str(e)}"

def process_gadget(gadget, mode_str):
    """Process a ROP gadget (multiple instructions separated by ;) and return formatted output."""
    gadget = gadget.strip()
    if not gadget or gadget.startswith('#'):
        return None
    
    # Determine architecture and mode
    if mode_str == "32":
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_32
    else:  # mode_str == "64"
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_64
    
    # Split gadget into individual instructions
    instructions = [inst.strip() for inst in gadget.split(';') if inst.strip()]
    
    results = []
    total_size = 0
    all_encodings = []
    failed = False
    
    # Process each instruction in the gadget
    for instruction in instructions:
        size, encoding = get_instruction_details(instruction, arch, mode)
        
        if size is not None:
            results.append({
                'instruction': instruction,
                'size': size,
                'encoding': encoding
            })
            total_size += size
            all_encodings.append(encoding.replace(' ', ''))
        else:
            results.append({
                'instruction': instruction,
                'size': 0,
                'encoding': f"ERROR: {encoding}"
            })
            failed = True
            break
    
    return {
        'gadget': gadget,
        'mode': mode_str,
        'instructions': results,
        'total_size': total_size,
        'total_encoding': ' '.join(all_encodings) if not failed else None,
        'failed': failed
    }

def format_gadget_output(result, verbose=False):
    """Format the gadget analysis results for display."""
    if result['failed']:
        return f"{Colors.FAIL}[{result['mode']}-bit]{Colors.ENDC} {result['gadget']:<50} | {Colors.FAIL}ERROR in gadget{Colors.ENDC}"
    
    output_lines = []
    
    # Main summary line
    mode_color = Colors.OKGREEN if result['mode'] == '32' else Colors.OKBLUE
    summary = f"{mode_color}[{result['mode']}-bit]{Colors.ENDC} {Colors.BOLD}{result['gadget']:<50}{Colors.ENDC} | {Colors.WARNING}{result['total_size']} bytes{Colors.ENDC} total"
    output_lines.append(summary)
    
    if verbose:
        # Detailed breakdown of each instruction
        for inst_data in result['instructions']:
            if 'ERROR' in inst_data['encoding']:
                detail = f"         └─ {Colors.FAIL}{inst_data['instruction']:<30}{Colors.ENDC} | {inst_data['encoding']}"
            else:
                detail = f"         └─ {Colors.OKCYAN}{inst_data['instruction']:<30}{Colors.ENDC} | {inst_data['size']} bytes | {Colors.HEADER}{inst_data['encoding']}{Colors.ENDC}"
            output_lines.append(detail)
        
        # Total encoding
        output_lines.append(f"         └─ {Colors.BOLD}{'Full gadget encoding:':<30}{Colors.ENDC} | {Colors.WARNING}{result['total_encoding']}{Colors.ENDC}")
    
    return '\n'.join(output_lines)

def is_gadget(line):
    """Check if a line contains a ROP gadget (multiple instructions with semicolons)."""
    return ';' in line

def process_instruction(instruction, mode_str):
    """Process a single instruction and return formatted output."""
    instruction = instruction.strip()
    if not instruction or instruction.startswith('#'):
        return None
    
    # Determine architecture and mode
    if mode_str == "32":
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_32
    else:  # mode_str == "64"
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_64
    
    size, encoding = get_instruction_details(instruction, arch, mode)
    
    mode_color = Colors.OKGREEN if mode_str == '32' else Colors.OKBLUE
    
    if size is not None:
        return f"{mode_color}[{mode_str}-bit]{Colors.ENDC} {Colors.BOLD}{instruction:<50}{Colors.ENDC} | {Colors.WARNING}{size} bytes{Colors.ENDC}      | {Colors.HEADER}{encoding}{Colors.ENDC}"
    else:
        return f"{mode_color}[{mode_str}-bit]{Colors.ENDC} {Colors.BOLD}{instruction:<50}{Colors.ENDC} | {Colors.FAIL}ERROR: {encoding}{Colors.ENDC}"

def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}Calculate x86/x86-64 instruction and ROP gadget sizes using Keystone assembler{Colors.ENDC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Colors.HEADER}Examples:{Colors.ENDC}
  {Colors.OKGREEN}# Single instruction (32-bit mode by default){Colors.ENDC}
  %(prog)s "mov eax, 1"
  
  {Colors.OKGREEN}# Single ROP gadget{Colors.ENDC}
  %(prog)s "pop eax ; ret"
  
  {Colors.OKGREEN}# ROP gadget in 64-bit mode{Colors.ENDC}
  %(prog)s -m 64 "pop rax ; pop rbx ; ret"
  
  {Colors.OKGREEN}# Process a file of instructions/gadgets{Colors.ENDC}
  %(prog)s -f gadgets.txt
  
  {Colors.OKGREEN}# Process a file with verbose output{Colors.ENDC}
  %(prog)s -f gadgets.txt -v
  
  {Colors.OKGREEN}# Process stdin{Colors.ENDC}
  echo "pop eax ; ret" | %(prog)s -f -
  
{Colors.HEADER}File format:{Colors.ENDC}
  • One instruction or gadget per line
  • Gadgets are multiple instructions separated by semicolons
  • Empty lines are ignored
  • Lines starting with # are treated as comments
  
{Colors.HEADER}Example file:{Colors.ENDC}
  {Colors.OKCYAN}# Single instructions{Colors.ENDC}
  mov eax, 1
  jmp esp
  
  {Colors.OKCYAN}# ROP gadgets{Colors.ENDC}
  pop eax ; ret
  pop ebx ; pop ecx ; ret
  xchg eax, esp ; ret

{Colors.HEADER}Tips:{Colors.ENDC}
  • Use {Colors.WARNING}-v{Colors.ENDC} for detailed gadget breakdown
  • Use {Colors.WARNING}-b{Colors.ENDC} to compare 32-bit vs 64-bit encodings
  • Use {Colors.WARNING}-g{Colors.ENDC} to filter only ROP gadgets from mixed input
  • Pipe gadgets from ROPgadget or other tools via stdin
        """,
        add_help=False  # We'll add custom help
    )
    
    # Custom help argument
    parser.add_argument(
        '-h', '--help',
        action='help',
        help=f'{Colors.BOLD}Show this help message and exit{Colors.ENDC}'
    )
    
    parser.add_argument(
        "instruction",
        nargs="?",
        help="Single instruction or gadget to analyze (if -f is not used)"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="File containing instructions/gadgets (one per line). Use '-' for stdin"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=["32", "64"],
        default="32",
        help="Assembly mode (default: 32)"
    )
    
    parser.add_argument(
        "-b", "--both",
        action="store_true",
        help="Show results for both 32-bit and 64-bit modes"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed breakdown for each instruction in gadgets"
    )
    
    parser.add_argument(
        "-g", "--gadgets-only",
        action="store_true",
        help="Only process lines that contain ROP gadgets (have semicolons)"
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't display the banner"
    )
    
    args = parser.parse_args()
    
    # Disable colors if requested or if output is not a terminal
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    
    # Show banner unless disabled
    if not args.no_banner:
        print(BANNER)
    
    # Validate arguments
    if not args.instruction and not args.file:
        parser.error("Either provide an instruction/gadget or use -f to specify a file")
    
    if args.instruction and args.file:
        parser.error("Cannot specify both an instruction and a file")
    
    # Collect instructions/gadgets
    lines = []
    
    if args.file:
        if args.file == "-":
            # Read from stdin
            for line in sys.stdin:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not args.gadgets_only or is_gadget(line):
                        lines.append(line)
        else:
            # Read from file
            if not os.path.exists(args.file):
                print(f"{Colors.FAIL}Error: File '{args.file}' not found{Colors.ENDC}", file=sys.stderr)
                sys.exit(1)
            
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not args.gadgets_only or is_gadget(line):
                            lines.append(line)
    else:
        lines = [args.instruction]
    
    if not lines:
        print(f"{Colors.FAIL}No instructions/gadgets to process{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)
    
    # Process instructions/gadgets
    print(f"{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    if args.verbose:
        print(f"{Colors.BOLD}{'Instruction/Gadget':<50} | Size{Colors.ENDC}")
    else:
        print(f"{Colors.BOLD}{'Instruction/Gadget':<50} | {'Size':<12} | Encoding{Colors.ENDC}")
    print(f"{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    
    for line in lines:
        if is_gadget(line):
            # Process as gadget
            if args.both:
                # Show both 32-bit and 64-bit results
                result_32 = process_gadget(line, "32")
                result_64 = process_gadget(line, "64")
                
                if result_32:
                    print(format_gadget_output(result_32, args.verbose))
                if result_64:
                    print(format_gadget_output(result_64, args.verbose))
                
                # Add separator between gadgets when showing both modes
                if line != lines[-1]:
                    print(f"{Colors.BOLD}{'-' * 80}{Colors.ENDC}")
            else:
                # Show only the specified mode
                result = process_gadget(line, args.mode)
                if result:
                    print(format_gadget_output(result, args.verbose))
        else:
            # Process as single instruction (backward compatibility)
            if args.both:
                # Show both 32-bit and 64-bit results
                result_32 = process_instruction(line, "32")
                result_64 = process_instruction(line, "64")
                
                if result_32:
                    print(result_32)
                if result_64:
                    print(result_64)
                
                # Add separator between instructions when showing both modes
                if line != lines[-1]:
                    print(f"{Colors.BOLD}{'-' * 80}{Colors.ENDC}")
            else:
                # Show only the specified mode
                result = process_instruction(line, args.mode)
                if result:
                    print(result)
    
    print(f"{Colors.BOLD}{'=' * 80}{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Unexpected error: {str(e)}{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)
