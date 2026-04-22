# mdb — Minimal Debugger

A GDB-like debugger for x86-64 Linux binaries built on top of `ptrace`.

## Dependencies

```bash
sudo apt install libreadline-dev libcapstone-dev libelf-dev
```

## Build

```bash
gcc -Wall min_gdb.c -lreadline -lcapstone -lelf -o mdb
```

## Usage

```bash
./mdb <program>
```

On startup, mdb loads the symbol table from the binary and drops into a pre-run REPL where you set breakpoints before execution begins. Type `r` to start the program.

## Commands

### Pre-run REPL

| Command | Description |
|---|---|
| `b <addr>` | Set breakpoint at hex address (e.g. `b 0x401126`) |
| `b <symbol>` | Set breakpoint at symbol name (e.g. `b main`) |
| `d <id>` | Delete breakpoint by id |
| `l` | List all breakpoints |
| `r` | Run the program |

### Post-run REPL (when stopped at a breakpoint)

| Command | Description |
|---|---|
| `c` | Continue execution |
| `s` | Single-step one instruction |
| `regs` | Display all registers |
| `disas` | Disassemble 10 instructions from current `rip` |
| `b <addr/symbol>` | Set a new breakpoint |
| `d <id>` | Delete breakpoint by id |
| `l` | List all breakpoints |

## Features

- Set breakpoints by address or symbol name
- Breakpoints are re-armed automatically — they trigger every time, including inside loops
- Disassembly via libcapstone with symbol resolution in operands (e.g. `call [printf]`)
- ELF symbol table and dynamic symbol table parsing via libelf
- Full x86-64 register display
- Readline support — arrow keys, command history
- Stable breakpoint IDs — deleting a breakpoint does not shift the IDs of others

## Example

```
$ ./mdb ./test1
Loaded 28 symbols from ./test1
mdb> b foo
Breakpoint 0 set at 0x401126
mdb> r
Breakpoint 0 hit at 0x401126
  foo:
  0x0000000000401126:  cc                    int3
  0x0000000000401127:  48 89 e5              mov rbp, rsp
  ...
mdb> regs
  rip = 0x0000000000401126  rsp = 0x00007fff...
mdb> c
Hello World.
```
