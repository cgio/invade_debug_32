# invade_debug_32

invade_debug_32 is an non-attaching debugging tool for 32-bit Windows processes. Current functionality includes stepping through instructions and viewing registers. invade_debug_32 is best used in conjunction with other dynamic and static analysis tools. The simulated debugging works via the "EBFE trick," similar to a JMP to EIP (self).

This project is also an example plugin module for [Invade](https://github.com/cgio/invade).

![invade_debug_32](https://i.imgur.com/vfnTVaA.png "invade_debug_32")

To use, you should have the target's current PID (e.g. via invade.Scout()) and a starting memory address (e.g. invade.Target.base_address + invade.Target.entry_point_address) for debugging.

Overall, the concept works as follows:

1. Memory is allocated in target process for shellcode injection.
2. Shellcode is injected and detour/hook is placed at `address`.
3. Execution enters shellcode. Shellcode stores register values and other debugging data.
4. Execution encounters EBFE in shellcode, which "pauses" execution.
5. Debug data is read (i.e. 32-bit registers) by invade_debug_32.py and displayed to the user.
6. User opts to continue, a new hook is placed for the next instruction, new debug data is displayed, etc.

Project status is early-stage. 64-bit support may come later.

## Usage

#### Command-line:

`python invade_debug_32.py [pid] [address]`

`pid` specifies the target's PID

`address` specifies breakpoint memory address within target

Decimal or hexadecimal (prefix with "0x") values are accepted.

#### Python example:

```python
import invade
import invade_debug_32

scout = invade.Scout('target', contains=True)
pid = scout.pids[0]
target = invade.Target(pid)
target_ep = 0
with target:
    if target.base_address:
        target_ep = target.base_address + target.entry_point_address
if target_ep:
    debugger = invade_debug_32.Main(target.pid, target_ep)
    with debugger:
        debugger.start(target_ep)
```

## Requirements

* [Python 3.6+](https://www.python.org/downloads/)
* [Invade 0.0.6+](https://github.com/cgio/invade)
* A target 32-bit x86 Windows process

## Files

* **invade_debug_32.py:** main project file
* **shellcode_32.py:** shellcode build script

## Authors
Chad Gosselin ([https://github.com/cgio](https://github.com/cgio))

## License
This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details. This project is for educational purposes only. Use at your own risk.