"""invade_debug_32
v0.0.1
"""

import argparse
import sys
import time

import invade

import shellcode_32

__version__ = '0.0.1'


class Args(object):
    """Receives command-line arguments.

    Attributes:
        args (object): argparse.ArgumentParser().

    """

    def __init__(self):
        self.args = None
        _parser = argparse.ArgumentParser()
        _parser.add_argument(
            'pid',
            help='target PID (default: decimal, use 0x prefix for hex)',
            type=str
        )
        _parser.add_argument(
            'address',
            help='virtual memory address to debug/hook (default: decimal, use '
                 '0x prefix for hex)',
            type=str
        )
        self.args = _parser.parse_args()


class Main(object):
    """Invade debugger class/plugin for 32-bit x86 Windows processes.

    Args:
        pid (int): target PID.
        address (int): address to start debugging.

    Attributes:
        pid (int): target PID.
        addr_start (int): address to start debugging.
        asm_current (dict): current instruction (EIP) assembly info.
        asm_next (dict): next instruction assembly info.
        pause_time (float): breakpoint hit check interval (in seconds).
        me (object): instance of invade.Me().
        target (object): instance of invade.Target().
        addr_shellcode (int): address of allocated shellcode memory.
        addr_shellcode_loop (int): address of shellcode 'EBFE' or '9090'.
        addr_shellcode_data (int): address of shellcode data start.
        data (dict): contains operational data.

    """

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.target.process_handle:
                invade.Tool.close_handle(self.target.process_handle)
        except AttributeError:
            pass

    def __init__(self, pid, address):
        self.pid = self._format_arg(pid)
        self.addr_start = self._format_arg(address)
        self.asm_current = {'addr': self.addr_start, 'asm': '', 'mc': ''}
        self.asm_next = {'addr': 0, 'asm': ''}
        self.pause_time = 0.5
        self.me = invade.Me()
        self.__init_me()
        self.target = invade.Target(self.pid)
        self.__init_target()
        self.addr_shellcode = self.__init_shellcode(0x1000)
        self.addr_shellcode_loop = self.addr_shellcode + 0x46
        self.addr_shellcode_data = self.addr_shellcode + 0x60
        __addr_shellcode_data = self.addr_shellcode_data
        self.data = {
            # 'eax': [__addr_shellcode_data, None],
            # 'ebx': [__addr_shellcode_data + 0x4, None],
            # 'ecx': [__addr_shellcode_data + 0x8, None],
            # 'edx': [__addr_shellcode_data + 0xc, None],
            # 'ebp': [__addr_shellcode_data + 0x10, None],
            # 'esp': [__addr_shellcode_data + 0x14, None],
            # 'esi': [__addr_shellcode_data + 0x18, None],
            # 'edi': [__addr_shellcode_data + 0x1c, None],
            'paused': [__addr_shellcode_data + 0x20, None],
            'jmp': [__addr_shellcode_data + 0x24, None]}

    def __init_me(self):
        if not self.me.is_windows:
            sys.exit('Error: Windows is required')
        if not self.me.is_windows_admin:
            print('Warning: not running as Windows admin')
        if not self.me.is_debug_privilege_enabled:
            sys.exit('Error: unable to set debug privileges')

    def __init_target(self):
        if not self.target.is_active:
            sys.exit('Error: target is not running')
        if self.target.is_x64 and not self.me.is_x64:
            print('Warning: target is 64-bit. Use Python 64-bit instead.')
        print(f'Target PID: {self.target.pid} ({hex(self.target.pid)})')

    def __init_shellcode(self, size):
        addr_shellcode = invade.Tool.memory_allocate(
            self.target.process_handle, size)
        if not addr_shellcode:
            sys.exit('Error: memory allocate')
        print(f'Shellcode memory allocated at: '
              f'{addr_shellcode} ({hex(addr_shellcode)})')
        self._mem_write(addr_shellcode, shellcode_32.get(self.target.is_x64,
                                                         addr_shellcode))
        print('Shellcode successfully written')
        return addr_shellcode

    @staticmethod
    def _format_arg(arg):
        if type(arg) is str:
            return int(arg, 0)
        return arg

    def _mem_read(self, addr, size):
        """Read memory."""
        mc = invade.Tool.memory_read(self.target.process_handle, addr, size,
                                     True)
        if not mc:
            sys.exit('Error: memory read')
        return mc

    def _mem_write(self, addr, mc):
        """Write memory."""
        if not invade.Tool.memory_write(self.target.process_handle, addr, mc,
                                        False):
            sys.exit('Error: memory write')
        return

    def _get_asm_max(self, addr):
        """Get a list of assembly info for 15 bytes at addr."""
        mc_max = self._get_mc_max(addr)
        if not mc_max:
            sys.exit('Error: memory read')
        asm_max = invade.Tool.get_asm(self.target.is_x64, mc_max, address=addr)
        if not asm_max:
            sys.exit('Error: disassembly')
        return asm_max

    def _get_mc_max(self, addr):
        """Get machine code byte string 15 bytes in size at addr."""
        mc_max = self._mem_read(addr, invade.X86_MC_INSN_MAX)
        return mc_max

    def _get_mc_jmp(self, addr_src, addr_dst):
        """Get machine code byte string for a JMP hook from addr_src to
        addr_dst.
        """
        mc_jmp = invade.Tool.get_mc(self.target.is_x64, 'jmp ' + hex(addr_dst),
                                    address=addr_src)
        if not mc_jmp:
            sys.exit('Error: assembly')
        return mc_jmp

    def _set_asm_current_next(self, addr, asm_max):
        """Set self.asm_current and self.asm_next values.

        This is a shellcode-specific method.
        """
        if len(asm_max) > 1:
            # Common: more than one instruction
            self.asm_current = asm_max[0]
            self.asm_next = asm_max[1]
        elif len(asm_max) == 1:
            try:
                # Uncommon: single instruction's size is 15 bytes
                asm_next_max = self._get_asm_max(addr + invade.X86_MC_INSN_MAX)
                self.asm_next = asm_next_max[0]
            except IndexError:
                # Semi-common: cannot disassemble next instruction
                print(f'Error: disassembly at {hex(addr)}')
        else:
            sys.exit('Error: unexpected')
        return

    def _set_mc(self, addr, asm):
        """Set (write) machine code to addr from asm."""
        mc = invade.Tool.get_mc(self.target.is_x64, asm, address=addr)
        if not mc:
            sys.exit('Error: assembly')
        self._mem_write(addr, mc)
        return invade.Tool.get_mc_size(mc)

    def _set_mc_jmp(self, addr_src, addr_dst):
        """Set (write) a JMP at addr for hooking."""
        mc_jmp = self._get_mc_jmp(addr_src, addr_dst)
        self._mem_write(addr_src, mc_jmp)
        return invade.Tool.get_mc_size(mc_jmp)

    def _set_mc_orig(self):
        """Save original machine code byte string replaced by JMP hook."""
        mc_jmp = self._get_mc_jmp(self.asm_current['addr'],
                                  self.addr_shellcode)
        mc_jmp_size = invade.Tool.get_mc_size(mc_jmp)
        mc_orig = self._mem_read(self.asm_current['addr'], mc_jmp_size)
        self.asm_current['mc'] = mc_orig
        return

    def _set_mc_shellcode_jmp_ptr(self):
        """Set (write) the JMP pointer value for returning to current addr.

        This is a shellcode-specific method.
        """
        self.data['jmp'][1] = invade.Tool.convert_int_pointer_to_str_hex(
            self.asm_current['addr'])
        if not self.data['jmp'][1]:
            sys.exit('Error: pointer')
        self._mem_write(self.data['jmp'][0], self.data['jmp'][1])
        return invade.Tool.get_mc_size(self.data['jmp'][1])

    def _pause(self):
        """Sleep until shellcode sets paused flag to '01'.

        This is a shellcode-specific method.
        """
        data_paused = None
        while self.target.is_active and data_paused != '01':
            data_paused = self._mem_read(self.data['paused'][0], 1)
            time.sleep(self.pause_time)
        self.data['paused'][1] = data_paused
        return

    @staticmethod
    def _asm_is_eip_change(asm):
        """Check if assembly instruction will change EIP.

        This is a shellcode-specific method.
        """
        if asm.lower().startswith(('j', 'call', 'ret', 'iret', 'int', 'sys')):
            return True
        return False

    def print_current(self):
        # This is a shellcode-specific method.
        try:
            print(f'EIP: ' + (f'{self.asm_current["addr"]:X}'.zfill(8))
                  + f'\t{self.asm_current["asm"]}')
        except KeyError:
            print('EIP: None')
        return

    def print_next(self):
        # This is a shellcode-specific method.
        try:
            print(f'Nxt: ' + (f'{self.asm_next["addr"]:X}'.zfill(8))
                  + f'\t{self.asm_next["asm"]}')
        except KeyError:
            print('Nxt: None')
        return

    def print_data(self, col=2):
        # This is a shellcode-specific method.
        data = self._mem_read(self.addr_shellcode_data, 0x20)
        data_list = []
        reg_list = ('EAX', 'EBX', 'ECX', 'EDX', 'EBP', 'ESP', 'ESI', 'EDI')
        for i in range(0, len(data), 8):
            val = bytearray.fromhex(data[i:i + 8])
            val.reverse()
            data_list.append(val.hex().upper())
        reg = dict(zip(reg_list, data_list))
        data_row = ''
        col_count = 1
        for key, val in reg.items():
            data_row += f'{key}: {val}\t'
            if col_count == col:
                print(data_row.strip())
                data_row = ''
                col_count = 1
                continue
            col_count += 1
        if data_row:
            print(data_row.strip())
        return

    def start(self, addr):

        print(f'Started debugging at: {addr} ({hex(addr)})')
        user_input = 'y'
        while user_input == 'y':

            # Read 15 bytes of memory at addr and convert to assembly
            asm_max = self._get_asm_max(addr)

            # Save assembly info for current and next instructions
            self._set_asm_current_next(addr, asm_max)

            # Check for EIP-changing instruction
            if self._asm_is_eip_change(self.asm_current['asm']):
                # TODO: Calculate destination instead.
                sys.exit(f'Error: current instruction at '
                         f'{hex(self.asm_current["addr"])} changes EIP. Sorry,'
                         f' such instructions are not yet supported.')

            # Save original machine code later replaced by hook
            self._set_mc_orig()

            # Hook current address
            self._set_mc_jmp(self.asm_current['addr'], self.addr_shellcode)

            if self.data['paused'][1] == '01':
                self._mem_write(self.data['paused'][0], '00')
                self._mem_write(self.addr_shellcode_loop, '9090')

            # Wait until target pauses
            print('Waiting...')
            self._pause()

            # Target is now paused (executing shellcode JMP loop)

            # In case target is no longer running after pause
            if not self.target.is_active:
                break

            # Unhook current address
            self._mem_write(self.asm_current['addr'], self.asm_current['mc'])

            # Set JMP pointer to return from shellcode
            self._set_mc_shellcode_jmp_ptr()

            print('=' * 16)
            self.print_data(col=4)
            self.print_current()
            self.print_next()

            # TODO: Offer -d [addr/reg] [size] to dump memory.

            user_input = input('Continue? (y/n): ').lower()

            # Prepare for next iteration
            addr = self.asm_next['addr']
            self.asm_current = {'addr': 0, 'asm': '', 'mc': ''}
            self.asm_next = {'addr': 0, 'asm': ''}

        # TODO: Offer to unhook and deallocate shellcode.

        sys.exit('Session ended')


def main():
    # Command-line use
    print(f'{sys.argv[0].rsplit("/", 1)[-1]} using invade v{invade.VERSION}')
    args = Args().args
    debugger = Main(args.pid, args.address)
    with debugger:
        debugger.start(debugger.addr_start)


if __name__ == '__main__':
    main()
