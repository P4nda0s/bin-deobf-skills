import angr
import claripy
import keystone
from pwn import *
import logging

logger = logging.getLogger("deinbr")
logger.setLevel(logging.INFO)


def parse_csel(insn):
    """解析 csel 指令，返回 (dst_reg, condition, reg1, reg2)"""
    if insn.mnemonic != 'csel':
        return None
    ops = insn.op_str.replace(' ', '').split(',')
    return ops[0], ops[3], ops[1], ops[2]


def parse_cset(insn):
    """解析 cset 指令，返回 (dst_reg, condition)"""
    if insn.mnemonic != 'cset':
        return None
    ops = insn.op_str.replace(' ', '').split(',')
    return ops[0], ops[1]


def run_until_br(proj, entry_state, csel_selector=1):
    """
    从 entry_state 执行到 BR 指令，遇到 CSEL 时按 csel_selector 强制选择。
    返回 BR 后的 state，遇到 RET 返回 None。
    """
    state = entry_state.copy()
    state.options.update({
        angr.options.CALLLESS,
        angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    })

    while True:
        insn = state.block().capstone.insns[0]

        if insn.mnemonic == 'ret':
            return None

        if insn.mnemonic == 'csel':
            dst, cond, reg1, reg2 = parse_csel(insn)
            val = state.regs.get(reg1) if csel_selector == 1 else state.regs.get(reg2)
            setattr(state.regs, dst, val)
            state.globals['csel_addr'] = insn.address
            state.globals['csel_condition'] = cond
            logger.info("execute %x csel %s select: %d" % (insn.address, insn.op_str, csel_selector))
            state.regs.pc += 4
            continue

        if insn.mnemonic == 'cset':
            dst, cond = parse_cset(insn)
            val = 1 if csel_selector == 1 else 0
            setattr(state.regs, dst, claripy.BVV(val, 32))
            state.globals['csel_addr'] = insn.address
            state.globals['csel_condition'] = cond
            logger.info("execute %x cset %s select: %d" % (insn.address, insn.op_str, csel_selector))
            state.regs.pc += 4
            continue

        successors = proj.factory.successors(state, num_inst=1).successors
        if len(successors) != 1:
            raise RuntimeError("block %x: expected 1 successor, got %d" % (state.addr, len(successors)))
        state = successors[0]

        if insn.mnemonic == 'br':
            return state


def analyze_br(proj, func_start):
    """BFS 遍历函数，收集所有 (csel_addr, condition, true_target, false_target) patch 点。"""
    patch_list = []
    visited = set()
    work_list = [proj.factory.blank_state(addr=func_start)]

    while work_list:
        init_state = work_list.pop(0)
        if init_state.addr in visited:
            continue
        visited.add(init_state.addr)

        s1 = run_until_br(proj, init_state, csel_selector=1)
        s2 = run_until_br(proj, init_state, csel_selector=2)
        logger.info("block: %x, next_1: %s, next_2: %s" % (init_state.addr, s1, s2))

        if s1 is None and s2 is None:
            continue

        if s1.globals['csel_addr'] != s2.globals['csel_addr']:
            raise RuntimeError("block %x: inconsistent csel addresses" % init_state.addr)

        patch_list.append((
            s1.globals['csel_addr'],
            s1.globals['csel_condition'],
            s1.addr,
            s2.addr,
        ))

        work_list.append(s1)
        work_list.append(s2)

    # 去重：同一个 csel 地址只保留一条 patch
    seen = set()
    deduped = []
    for item in patch_list:
        if item[0] not in seen:
            seen.add(item[0])
            deduped.append(item)
    return deduped


def do_patch(binary_path, save_path, proj, patch_list):
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    image_base = proj.loader.main_object.mapped_base
    elf = ELF(binary_path)
    elf_base = elf.address

    for csel_addr, condition, true_addr, false_addr in patch_list:
        asm_code = "b%s 0x%x; b 0x%x" % (condition, true_addr, false_addr)
        logger.info("patch %x: %s" % (csel_addr, asm_code))
        opcode, _ = ks.asm(asm_code, csel_addr)
        file_offset = csel_addr - image_base + elf_base
        elf.write(file_offset, bytes(opcode))

    elf.save(save_path)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    binary_path = sys.argv[1] if len(sys.argv) > 1 else './tests/goron-indbr-miniz-example2'
    save_path = binary_path + '.patched'
    proj = angr.Project(binary_path, auto_load_libs=False)
    image_base = proj.loader.main_object.mapped_base

    funcs = [int(x, 16) + image_base for x in sys.argv[2:]] if len(sys.argv) > 2 else [image_base + 0x4BBA0]

    patch_list = []
    for func in funcs:
        patch_list += analyze_br(proj, func)

    print("patch list (%d):" % len(patch_list))
    for csel_addr, condition, true_addr, false_addr in patch_list:
        print("  %x: b%s %x / b %x" % (csel_addr, condition, true_addr, false_addr))

    do_patch(binary_path, save_path, proj, patch_list)
    print("saved:", save_path)
