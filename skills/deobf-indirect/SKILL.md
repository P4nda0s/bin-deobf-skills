---
name: deobf-indirect
description: Deobfuscate indirect branches (CSEL + BR pattern) using symbolic execution and BFS traversal to recover control flow
---

# Deobfuscate Indirect Branches

## Part 1: CSEL + BR Indirect Branch Pattern

### Pattern Recognition

The obfuscator converts conditional branches into indirect jumps, where `CSEL` and `BR` instructions appear in pairs. `CSEL` selects one of two target addresses based on a condition, followed by some junk instructions, then `BR` jumps to the selected address.

Typical instruction sequence:

```asm
CMP             W10, W11
CSEL            W10, W13, W12, LS   ; select W13 or W12 based on LS condition
......                               ; junk code in between (address calculations, etc.)
ADD             X8, X8, X14
BR              X8                   ; indirect jump to the computed target
```

Key characteristics:
- `CSEL` selects one of two register values, representing two branch targets
- Code between `CSEL` and `BR` is address calculation or junk code
- `BR` performs the final indirect jump

### Analysis Approach

Symbolic execution: when encountering a `CSEL` instruction, force different branch selections to obtain two different `BR` target addresses.

Steps:
1. Start two symbolic execution runs from the same basic block entry
2. First run: force `CSEL` to select the first register (condition-true branch)
3. Second run: force `CSEL` to select the second register (condition-false branch)
4. Each run reaches `BR` and yields a different target address (A and B)

### Traversal Strategy

BFS traversal starting from the function entry block:

1. Add the function entry address to the work queue
2. Dequeue an address, run symbolic execution with both `CSEL` selections until `BR`
3. Record patch info (CSEL address, condition, two target addresses)
4. Add both target addresses to the work queue
5. Use a visited set to prevent revisiting
6. Mark blocks ending with `RET` as return blocks — do not continue from them

### Patching Strategy

Code between `CSEL` and `BR` is junk — patch a conditional branch directly at the `CSEL` location.

For example, `CSEL W11, W8, W9, CC`: W8 is the target for the CC-true branch (A), W9 is the target for the CC-false branch (B).

Patch as:

```asm
BCC  A    ; if condition met, jump to A
B    B    ; otherwise jump to B
```

Two instructions = 8 bytes, overwriting the `CSEL` (4 bytes) and the next junk instruction (4 bytes).

### Reference Implementation

See `script/deinbr-v3.py` for the core workflow:

1. `analyze_br(proj, func_start)` — BFS traversal, collects all patch points
2. `run_until_br(proj, state, csel_selector)` — execute from a given state until BR, forcing CSEL selection
3. `do_patch(binary_path, save_path, proj, patch_list)` — assemble patches with keystone and write to binary

Key angr options:
- `CALLLESS` — ignore function calls to prevent analysis divergence
- `LAZY_SOLVES` — defer constraint solving for performance
- `ZERO_FILL_UNCONSTRAINED_MEMORY` — fill unconstrained memory with zeros
- `ZERO_FILL_UNCONSTRAINED_REGISTERS` — fill unconstrained registers with zeros

### Common Errors and Debugging

#### BR target is an invalid address

```
block: 41fe20, next_1: <SimState @ 0x2908f8c3>, next_2: <SimState @ 0x2908f8c3>
SimEngineError: No bytes in memory for block starting at 0x2908f8c3.
```

Cause: The user-provided address is not the function entry but an internal basic block. Stack-based jump table base addresses and offset constants have not been initialized (filled with zeros by ZERO_FILL), causing BR to compute an invalid target.

Solution: Confirm the address is the function start. Use the symbol table or IDA/Ghidra to find the function entry:
```python
for sym in proj.loader.main_object.symbols:
    if sym.rebased_addr <= target_addr < sym.rebased_addr + sym.size:
        print(sym.name, hex(sym.rebased_addr))
```

#### Both branch targets are identical

```
block: XXXXX, next_1: <SimState @ 0xABCD>, next_2: <SimState @ 0xABCD>
```

Same cause as above — starting execution from a non-entry point means the two registers selected by CSEL hold the same value (both zero or the same uninitialized value), producing the same BR target after address calculation.

Solution: Use the correct function entry address.

#### Encountering non-CSEL conditional select instructions

```
block XXXXX: expected 1 successor, got 0
```

Or the script reaches BR without detecting CSEL, so `csel_addr` is missing from globals.

Cause: The basic block uses `CSET` instead of `CSEL`. `CSET` is a special form of `CSEL`, equivalent to `CSEL Rd, WZR, WZR, invert(cond)`, selecting 1 or 0 as an index.

Handle the same way as `CSEL` — identify the condition and force both branch selections. The script must handle both `csel` and `cset`:

```python
if insn.mnemonic == 'cset':
    # cset Wd, cond  is equivalent to  csel Wd, #1, #0, cond (condition met=1, not met=0)
    dst, cond = parse_cset(insn)
    val = 1 if csel_selector == 1 else 0
    setattr(state.regs, dst, val)
    ...
```
