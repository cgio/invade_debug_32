"""invade_debug_32 shellcode build script
v0.0.1
Execute this script to test shellcode build
"""

import sys
import invade


def get(is_x64, addr=0x1000):
    """Get shellcode machine code byte string from "dynamic" assembly.

    Args:
        is_x64 (bool): If True, the process is x64.
        addr (int, optional): Destination memory address for shellcode. In
            production, this arg is required. It was made optional for testing
            purposes (i.e. see if your assembly assembles).

    Returns:
        str: A string of machine code bytes on success.
    """
    shellcode = ''
    addr_delta = addr

    # Data struct address
    shellcode_addr_data = addr + 0x60

    # JMP pointer value address
    shellcode_addr_data_jmp = shellcode_addr_data + 0x24

    # ========================================

    shellcode_1 = f'''
    pushfd
    pushad
    xor eax, eax
    mov edi, {hex(shellcode_addr_data)}
    mov ecx, 0x20
    rep stosb
    popad
    popfd
    pushfd
    pushad
    mov dword ptr [{hex(shellcode_addr_data)}], eax
    mov eax, {hex(shellcode_addr_data)}
    mov dword ptr [eax+4], ebx
    mov dword ptr [eax+0x8], ecx
    mov dword ptr [eax+0xc], edx
    mov dword ptr [eax+0x10], ebp
    lea ebx, dword ptr [esp+0x24]
    mov dword ptr [eax+0x14], ebx
    mov dword ptr [eax+0x18], esi
    mov dword ptr [eax+0x1c], edi
    mov byte ptr [eax+0x20], 0x1
    popad
    popfd
    '''

    # Build it thus far
    shellcode += invade.Tool.get_mc(is_x64, shellcode_1, address=addr_delta)
    addr_delta += invade.Tool.get_mc_size(shellcode)

    # ========================================

    # Get size of shellcode_2 (a self-modifying instruction)
    test_mc = f'''
    mov word ptr [{hex(addr + invade.Tool.get_mc_size(shellcode))}], 0xFEEB
    '''
    test_mc_len = invade.Tool.get_mc_size(invade.Tool.get_mc(is_x64, test_mc,
                                                            address=addr_delta))

    # Set pointer to next instruction for self-modification
    shellcode_2 = f'''
    mov word ptr [{hex(addr + invade.Tool.get_mc_size(shellcode) + 
    test_mc_len)}], 0xFEEB
    '''

    # Build it thus far
    shellcode += invade.Tool.get_mc(is_x64, shellcode_2, address=addr_delta)
    addr_delta += invade.Tool.get_mc_size(shellcode)

    # ========================================

    # "Pause execution" via JMP to EIP, aka the EB FE trick
    shellcode_3 = 'EBFE'

    # Build it thus far
    shellcode += shellcode_3
    addr_delta += invade.Tool.get_mc_size(shellcode)

    # ========================================

    shellcode_4 = f'''
    jmp dword ptr [{hex(shellcode_addr_data_jmp)}]
    '''

    # Build it thus far
    shellcode += invade.Tool.get_mc(is_x64, shellcode_4, address=addr_delta)
    addr_delta += invade.Tool.get_mc_size(shellcode)

    # ========================================

    return shellcode


if __name__ == '__main__':
    # Test unit
    test_pass = '''
    6031C0BF60100000B920000000F3AA6189256010000060BC6010000089442404895C240889
    4C240C89542410896C241489742418897C241CC6442420016166C70547100000EBFEEBFEFF
    2584100000
    '''
    test_pass = ''.join(test_pass.split())
    test = get(False, 0x1000)
    try:
        assert test == test_pass
    except AssertionError:
        sys.exit('Error: incorrect machine code')
    print('Success: correct machine code')
