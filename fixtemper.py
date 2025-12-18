#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI团队反汇编分析工具 v1.0

目标：
1. 深度反汇编分析，理解代码逻辑
2. 识别可修改的功能点
3. 生成补丁建议
4. AI多角色协作分析

功能：
- 反汇编引擎（支持x86/x64）
- 控制流分析
- 数据流分析
- 函数语义识别
- 补丁点识别
- AI团队多角色代码审查
"""

import os
import sys

# 确保 Windows 控制台支持 UTF-8
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
import json
import struct
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum, auto
from abc import ABC, abstractmethod
import hashlib

# 可选依赖
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("提示:  pip install pefile 以启用PE分析")

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError: 
    HAS_CAPSTONE = False
    print("提示: pip install capstone 以启用专业反汇编")

try:
    from keystone import *
    HAS_KEYSTONE = True
except ImportError:
    HAS_KEYSTONE = False
    print("提示:  pip install keystone-engine 以启用汇编功能")


# ============================================================================
# 基础数据结构
# ============================================================================

class InstructionType(Enum):
    """指令类型分类"""
    UNKNOWN = auto()
    DATA_TRANSFER = auto()      # mov, push, pop, lea
    ARITHMETIC = auto()         # add, sub, mul, div, inc, dec
    LOGIC = auto()              # and, or, xor, not, shl, shr
    CONTROL_FLOW = auto()       # jmp, call, ret, jcc
    COMPARISON = auto()         # cmp, test
    STRING = auto()             # movs, stos, lods, cmps
    STACK = auto()              # push, pop, enter, leave
    SYSTEM = auto()             # int, syscall, sysenter
    FLOATING_POINT = auto()     # fld, fst, fadd, etc. 
    SIMD = auto()               # SSE, AVX instructions
    NOP = auto()                # nop, padding
    PRIVILEGED = auto()         # ring0 instructions


class BranchType(Enum):
    """分支类型"""
    NONE = auto()
    UNCONDITIONAL = auto()      # jmp
    CONDITIONAL = auto()        # jcc
    CALL = auto()               # call
    RET = auto()                # ret
    INDIRECT = auto()           # jmp [eax], call [ebx]
    LOOP = auto()               # loop, loope, loopne


@dataclass
class Instruction:
    """反汇编指令"""
    address:  int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    instruction_type: InstructionType = InstructionType. UNKNOWN
    branch_type: BranchType = BranchType.NONE
    branch_target: Optional[int] = None
    is_call: bool = False
    is_ret:  bool = False
    is_jump: bool = False
    is_conditional:  bool = False
    reads:  List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    comment: str = ""
    
    def __str__(self):
        return f"0x{self.address:08x}:  {self.mnemonic} {self. op_str}"


@dataclass
class BasicBlock:
    """基本块"""
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors:  List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit:  bool = False
    loop_header: bool = False
    
    @property
    def size(self) -> int:
        return self.end_address - self.start_address
    
    def __str__(self):
        return f"BasicBlock(0x{self.start_address:08x} - 0x{self.end_address:08x}, {len(self. instructions)} instrs)"


@dataclass
class Function:
    """函数"""
    address: int
    name: str
    size: int = 0
    end_address: int = 0
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    calls: List[int] = field(default_factory=list)
    called_by: List[int] = field(default_factory=list)
    local_vars: List[Dict] = field(default_factory=list)
    arguments: List[Dict] = field(default_factory=list)
    return_type: str = "unknown"
    is_thunk: bool = False
    is_import: bool = False
    is_export: bool = False
    complexity: int = 0
    description: str = ""
    ai_analysis: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class PatchPoint:
    """可修改点"""
    address: int
    size: int
    original_bytes: bytes
    original_instruction: str
    patch_type: str
    description: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    suggested_patches: List[Dict] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    reversible: bool = True


# ============================================================================
# 反汇编引擎
# ============================================================================

class DisassemblyEngine:
    """反汇编引擎"""
    
    # x86指令信息表
    INSTRUCTION_INFO = {
        # 数据传输
        'mov': (InstructionType.DATA_TRANSFER, BranchType. NONE),
        'movzx': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'movsx': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'lea': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'xchg': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'push': (InstructionType.STACK, BranchType. NONE),
        'pop': (InstructionType. STACK, BranchType.NONE),
        'pushad': (InstructionType.STACK, BranchType. NONE),
        'popad': (InstructionType. STACK, BranchType.NONE),
        'pushfd': (InstructionType.STACK, BranchType.NONE),
        'popfd':  (InstructionType.STACK, BranchType. NONE),
        
        # 算术运算
        'add': (InstructionType.ARITHMETIC, BranchType.NONE),
        'sub': (InstructionType. ARITHMETIC, BranchType.NONE),
        'mul': (InstructionType.ARITHMETIC, BranchType. NONE),
        'imul': (InstructionType.ARITHMETIC, BranchType.NONE),
        'div': (InstructionType. ARITHMETIC, BranchType.NONE),
        'idiv': (InstructionType.ARITHMETIC, BranchType.NONE),
        'inc': (InstructionType.ARITHMETIC, BranchType. NONE),
        'dec': (InstructionType. ARITHMETIC, BranchType.NONE),
        'neg': (InstructionType.ARITHMETIC, BranchType.NONE),
        
        # 逻辑运算
        'and':  (InstructionType.LOGIC, BranchType. NONE),
        'or': (InstructionType.LOGIC, BranchType.NONE),
        'xor':  (InstructionType.LOGIC, BranchType. NONE),
        'not': (InstructionType.LOGIC, BranchType.NONE),
        'shl': (InstructionType. LOGIC, BranchType.NONE),
        'shr': (InstructionType.LOGIC, BranchType. NONE),
        'sar': (InstructionType. LOGIC, BranchType.NONE),
        'rol': (InstructionType.LOGIC, BranchType. NONE),
        'ror': (InstructionType. LOGIC, BranchType.NONE),
        
        # 比较
        'cmp':  (InstructionType.COMPARISON, BranchType. NONE),
        'test': (InstructionType.COMPARISON, BranchType.NONE),
        
        # 控制流
        'jmp': (InstructionType. CONTROL_FLOW, BranchType.UNCONDITIONAL),
        'je': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jz': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jne': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jnz': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'ja': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jae': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jb': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jbe': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jg': (InstructionType. CONTROL_FLOW, BranchType. CONDITIONAL),
        'jge': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jl': (InstructionType. CONTROL_FLOW, BranchType. CONDITIONAL),
        'jle': (InstructionType. CONTROL_FLOW, BranchType.CONDITIONAL),
        'js': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jns': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jo': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jno': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'call': (InstructionType.CONTROL_FLOW, BranchType.CALL),
        'ret': (InstructionType.CONTROL_FLOW, BranchType.RET),
        'retn': (InstructionType.CONTROL_FLOW, BranchType.RET),
        'loop': (InstructionType.CONTROL_FLOW, BranchType.LOOP),
        'loope': (InstructionType.CONTROL_FLOW, BranchType. LOOP),
        'loopne': (InstructionType.CONTROL_FLOW, BranchType.LOOP),
        
        # 字符串操作
        'movs': (InstructionType.STRING, BranchType. NONE),
        'movsb': (InstructionType.STRING, BranchType.NONE),
        'movsw': (InstructionType.STRING, BranchType.NONE),
        'movsd': (InstructionType.STRING, BranchType. NONE),
        'stos': (InstructionType.STRING, BranchType. NONE),
        'stosb': (InstructionType.STRING, BranchType. NONE),
        'stosw': (InstructionType.STRING, BranchType. NONE),
        'stosd': (InstructionType.STRING, BranchType. NONE),
        'lods': (InstructionType.STRING, BranchType. NONE),
        'cmps': (InstructionType.STRING, BranchType. NONE),
        'scas': (InstructionType.STRING, BranchType. NONE),
        'rep': (InstructionType.STRING, BranchType. NONE),
        
        # 系统
        'int': (InstructionType. SYSTEM, BranchType.NONE),
        'syscall': (InstructionType.SYSTEM, BranchType.NONE),
        'sysenter': (InstructionType. SYSTEM, BranchType.NONE),
        'cpuid': (InstructionType.SYSTEM, BranchType.NONE),
        'rdtsc': (InstructionType. SYSTEM, BranchType.NONE),
        
        # NOP
        'nop':  (InstructionType.NOP, BranchType. NONE),
        
        # 特权指令
        'cli': (InstructionType.PRIVILEGED, BranchType.NONE),
        'sti':  (InstructionType.PRIVILEGED, BranchType. NONE),
        'hlt': (InstructionType.PRIVILEGED, BranchType.NONE),
        'in': (InstructionType.PRIVILEGED, BranchType.NONE),
        'out': (InstructionType. PRIVILEGED, BranchType. NONE),
    }
    
    def __init__(self, arch:  str = 'x86', mode: str = '32'):
        self.arch = arch
        self.mode = mode
        self. cs = None
        self. ks = None
        
        # 初始化Capstone
        if HAS_CAPSTONE:
            if arch == 'x86':
                if mode == '64':
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
                else: 
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
                self.cs.detail = True
        
        # 初始化Keystone
        if HAS_KEYSTONE:
            if arch == 'x86':
                if mode == '64': 
                    self. ks = Ks(KS_ARCH_X86, KS_MODE_64)
                else:
                    self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
    
    def disassemble(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """反汇编代码"""
        instructions = []
        
        if HAS_CAPSTONE and self.cs:
            return self._disassemble_capstone(code, base_address)
        else:
            return self._disassemble_simple(code, base_address)
    
    def _disassemble_capstone(self, code: bytes, base_address: int) -> List[Instruction]: 
        """使用Capstone反汇编"""
        instructions = []
        
        for insn in self.cs.disasm(code, base_address):
            mnemonic = insn.mnemonic. lower()
            
            # 获取指令类型和分支类型
            inst_type, branch_type = self.INSTRUCTION_INFO.get(
                mnemonic, (InstructionType.UNKNOWN, BranchType. NONE)
            )
            
            # 解析分支目标
            branch_target = None
            if branch_type in [BranchType.UNCONDITIONAL, BranchType.CONDITIONAL, 
                              BranchType. CALL, BranchType. LOOP]:
                branch_target = self._parse_branch_target(insn)
            
            # 解析读写操作数
            reads, writes = self._parse_operands(insn)
            
            instr = Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                instruction_type=inst_type,
                branch_type=branch_type,
                branch_target=branch_target,
                is_call=(branch_type == BranchType. CALL),
                is_ret=(branch_type == BranchType.RET),
                is_jump=(branch_type in [BranchType.UNCONDITIONAL, BranchType.CONDITIONAL]),
                is_conditional=(branch_type == BranchType. CONDITIONAL),
                reads=reads,
                writes=writes
            )
            
            instructions.append(instr)
        
        return instructions
    
    def _disassemble_simple(self, code:  bytes, base_address: int) -> List[Instruction]: 
        """简单反汇编（无Capstone时使用）"""
        instructions = []
        offset = 0
        
        # 简单的x86指令解码
        simple_opcodes = {
            0x90: ('nop', 1),
            0xC3: ('ret', 1),
            0xCC: ('int3', 1),
            0x55: ('push ebp', 1),
            0x5D: ('pop ebp', 1),
            0x50: ('push eax', 1),
            0x51: ('push ecx', 1),
            0x52: ('push edx', 1),
            0x53: ('push ebx', 1),
            0x58: ('pop eax', 1),
            0x59: ('pop ecx', 1),
            0x5A: ('pop edx', 1),
            0x5B: ('pop ebx', 1),
            0xC9: ('leave', 1),
        }
        
        while offset < len(code):
            addr = base_address + offset
            opcode = code[offset]
            
            if opcode in simple_opcodes: 
                mnemonic, size = simple_opcodes[opcode]
                op_str = ""
                if ' ' in mnemonic:
                    parts = mnemonic. split(' ', 1)
                    mnemonic = parts[0]
                    op_str = parts[1]
            elif opcode == 0xE8:  # CALL rel32
                if offset + 5 <= len(code):
                    rel = struct.unpack('<i', code[offset+1:offset+5])[0]
                    target = addr + 5 + rel
                    mnemonic = 'call'
                    op_str = f'0x{target:x}'
                    size = 5
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode:02x}'
                    size = 1
            elif opcode == 0xE9:  # JMP rel32
                if offset + 5 <= len(code):
                    rel = struct.unpack('<i', code[offset+1:offset+5])[0]
                    target = addr + 5 + rel
                    mnemonic = 'jmp'
                    op_str = f'0x{target: x}'
                    size = 5
                else:
                    mnemonic = 'db'
                    op_str = f'0x{opcode:02x}'
                    size = 1
            elif opcode == 0xEB:  # JMP rel8
                if offset + 2 <= len(code):
                    rel = struct. unpack('<b', code[offset+1:offset+2])[0]
                    target = addr + 2 + rel
                    mnemonic = 'jmp'
                    op_str = f'short 0x{target:x}'
                    size = 2
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode: 02x}'
                    size = 1
            elif 0x70 <= opcode <= 0x7F:  # Jcc rel8
                jcc_names = ['jo', 'jno', 'jb', 'jnb', 'jz', 'jnz', 'jbe', 'ja',
                            'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
                if offset + 2 <= len(code):
                    rel = struct.unpack('<b', code[offset+1:offset+2])[0]
                    target = addr + 2 + rel
                    mnemonic = jcc_names[opcode - 0x70]
                    op_str = f'short 0x{target:x}'
                    size = 2
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode: 02x}'
                    size = 1
            else:
                # 未知指令，作为数据处理
                mnemonic = 'db'
                op_str = f'0x{opcode: 02x}'
                size = 1
            
            # 获取指令类型
            inst_type, branch_type = self.INSTRUCTION_INFO.get(
                mnemonic, (InstructionType. UNKNOWN, BranchType.NONE)
            )
            
            instr = Instruction(
                address=addr,
                size=size,
                mnemonic=mnemonic,
                op_str=op_str,
                bytes=code[offset:offset+size],
                instruction_type=inst_type,
                branch_type=branch_type,
                is_call=(mnemonic == 'call'),
                is_ret=(mnemonic in ['ret', 'retn']),
                is_jump=(mnemonic in ['jmp'] or mnemonic. startswith('j')),
                is_conditional=(0x70 <= opcode <= 0x7F)
            )
            
            instructions.append(instr)
            offset += size
        
        return instructions
    
    def _parse_branch_target(self, insn) -> Optional[int]: 
        """解析分支目标地址"""
        if len(insn.operands) > 0:
            op = insn. operands[0]
            if op. type == CS_OP_IMM:
                return op.imm
        return None
    
    def _parse_operands(self, insn) -> Tuple[List[str], List[str]]:
        """解析操作数的读写"""
        reads = []
        writes = []
        
        try:
            regs_read, regs_write = insn.regs_access()
            reads = [insn.reg_name(r) for r in regs_read]
            writes = [insn.reg_name(r) for r in regs_write]
        except Exception:
            pass
        
        return reads, writes
    
    def assemble(self, assembly:  str, address:  int = 0) -> Optional[bytes]:
        """汇编代码"""
        if not HAS_KEYSTONE or not self. ks:
            print("错误:  需要Keystone引擎进行汇编")
            return None
        
        try:
            encoding, count = self.ks. asm(assembly, address)
            return bytes(encoding)
        except Exception as e:
            print(f"汇编错误:  {e}")
            return None


# ============================================================================
# 控制流分析器
# ============================================================================

class ControlFlowAnalyzer: 
    """控制流分析器"""
    
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        self.addr_to_instr = {i.address: i for i in instructions}
        self.basic_blocks:  Dict[int, BasicBlock] = {}
        self.functions: Dict[int, Function] = {}
    
    def build_basic_blocks(self) -> Dict[int, BasicBlock]:
        """构建基本块"""
        if not self.instructions:
            return {}
        
        # 找出所有基本块的起始地址
        leaders = {self.instructions[0]. address}
        
        for i, instr in enumerate(self.instructions):
            # 分支目标是leader
            if instr. branch_target and instr.branch_target in self.addr_to_instr:
                leaders.add(instr.branch_target)
            
            # 分支指令后面的指令是leader
            if instr.is_jump or instr.is_call or instr.is_ret:
                if i + 1 < len(self.instructions):
                    leaders.add(self. instructions[i + 1].address)
        
        # 构建基本块
        sorted_leaders = sorted(leaders)
        
        for i, leader_addr in enumerate(sorted_leaders):
            # 找到块的结束
            end_addr = leader_addr
            block_instrs = []
            
            for instr in self.instructions:
                if instr.address < leader_addr:
                    continue
                if i + 1 < len(sorted_leaders) and instr.address >= sorted_leaders[i + 1]: 
                    break
                
                block_instrs.append(instr)
                end_addr = instr.address + instr.size
                
                # 如果是分支指令，结束当前块
                if instr. is_jump or instr.is_ret:
                    break
            
            if block_instrs: 
                bb = BasicBlock(
                    start_address=leader_addr,
                    end_address=end_addr,
                    instructions=block_instrs
                )
                self.basic_blocks[leader_addr] = bb
        
        # 建立块之间的关系
        self._build_block_edges()
        
        return self.basic_blocks
    
    def _build_block_edges(self):
        """建立基本块之间的边"""
        for addr, block in self. basic_blocks.items():
            if not block.instructions:
                continue
            
            last_instr = block.instructions[-1]
            
            # 无条件跳转
            if last_instr.branch_type == BranchType.UNCONDITIONAL:
                if last_instr. branch_target in self.basic_blocks:
                    block.successors.append(last_instr.branch_target)
                    self.basic_blocks[last_instr.branch_target].predecessors.append(addr)
            
            # 条件跳转
            elif last_instr. branch_type == BranchType. CONDITIONAL:
                # 跳转目标
                if last_instr.branch_target in self.basic_blocks:
                    block.successors. append(last_instr.branch_target)
                    self.basic_blocks[last_instr. branch_target].predecessors.append(addr)
                
                # fall-through
                next_addr = last_instr.address + last_instr.size
                if next_addr in self.basic_blocks:
                    block. successors.append(next_addr)
                    self.basic_blocks[next_addr].predecessors. append(addr)
            
            # 返回指令
            elif last_instr. branch_type == BranchType.RET:
                block.is_exit = True
            
            # 普通指令 - fall-through
            else:
                next_addr = last_instr.address + last_instr.size
                if next_addr in self.basic_blocks:
                    block.successors.append(next_addr)
                    self.basic_blocks[next_addr]. predecessors.append(addr)
    
    def detect_loops(self) -> List[Dict]:
        """检测循环"""
        loops = []
        
        for addr, block in self.basic_blocks.items():
            # 回边检测：后继指向自己或祖先
            for succ in block. successors:
                if succ <= addr:  # 简单的回边检测
                    loop = {
                        'header': succ,
                        'back_edge_from': addr,
                        'type': 'natural_loop'
                    }
                    loops.append(loop)
                    
                    if succ in self. basic_blocks: 
                        self.basic_blocks[succ].loop_header = True
        
        return loops
    
    def calculate_complexity(self) -> int:
        """计算圈复杂度"""
        # V(G) = E - N + 2P
        # E = 边数, N = 节点数, P = 连通分量数
        edges = sum(len(bb.successors) for bb in self.basic_blocks.values())
        nodes = len(self.basic_blocks)
        components = 1  # 假设单个函数是连通的
        
        return edges - nodes + 2 * components
    
    def identify_functions(self) -> Dict[int, Function]:
        """识别函数"""
        # 通过函数序言识别
        function_starts = set()
        
        for instr in self.instructions:
            # 常见的函数序言
            if (instr.mnemonic == 'push' and 'ebp' in instr.op_str. lower()) or \
               (instr.mnemonic == 'push' and 'rbp' in instr.op_str. lower()):
                # 检查下一条是否是 mov ebp, esp
                idx = self.instructions.index(instr)
                if idx + 1 < len(self.instructions):
                    next_instr = self.instructions[idx + 1]
                    if next_instr.mnemonic == 'mov' and \
                       ('ebp' in next_instr.op_str.lower() or 'rbp' in next_instr.op_str.lower()):
                        function_starts.add(instr.address)
            
            # sub rsp 模式（x64）
            elif instr.mnemonic == 'sub' and 'rsp' in instr. op_str.lower():
                function_starts.add(instr.address)
        
        # 通过CALL目标识别
        for instr in self.instructions:
            if instr.is_call and instr.branch_target:
                if instr.branch_target in self.addr_to_instr:
                    function_starts.add(instr.branch_target)
        
        # 创建函数对象
        sorted_starts = sorted(function_starts)
        
        for i, start_addr in enumerate(sorted_starts):
            # 估算函数结束地址
            end_addr = start_addr
            for instr in self.instructions:
                if instr.address < start_addr:
                    continue
                if i + 1 < len(sorted_starts) and instr.address >= sorted_starts[i + 1]: 
                    break
                end_addr = instr.address + instr.size
                if instr.is_ret:
                    break
            
            func = Function(
                address=start_addr,
                name=f"sub_{start_addr: x}",
                size=end_addr - start_addr,
                end_address=end_addr
            )
            
            # 收集函数内的基本块
            for bb_addr, bb in self.basic_blocks.items():
                if start_addr <= bb_addr < end_addr:
                    func.basic_blocks. append(bb)
            
            # 收集调用目标
            for instr in self.instructions:
                if start_addr <= instr.address < end_addr:
                    if instr.is_call and instr.branch_target:
                        func.calls.append(instr.branch_target)
            
            self.functions[start_addr] = func
        
        return self.functions


# ============================================================================
# 数据流分析器
# ============================================================================

class DataFlowAnalyzer:
    """数据流分析器"""
    
    def __init__(self, basic_blocks: Dict[int, BasicBlock]):
        self.basic_blocks = basic_blocks
        self. definitions: Dict[int, Set[str]] = {}  # 块定义的变量
        self. uses: Dict[int, Set[str]] = {}          # 块使用的变量
        self.live_in: Dict[int, Set[str]] = {}       # 块入口活跃变量
        self.live_out: Dict[int, Set[str]] = {}      # 块出口活跃变量
    
    def analyze_definitions_and_uses(self):
        """分析定义和使用"""
        for addr, block in self.basic_blocks. items():
            defs = set()
            uses = set()
            
            for instr in block. instructions:
                # 使用在定义之前
                for r in instr.reads:
                    if r not in defs: 
                        uses.add(r)
                
                # 定义
                for w in instr.writes:
                    defs.add(w)
            
            self.definitions[addr] = defs
            self.uses[addr] = uses
    
    def compute_liveness(self):
        """计算活跃性分析"""
        self.analyze_definitions_and_uses()
        
        # 初始化
        for addr in self.basic_blocks:
            self. live_in[addr] = set()
            self.live_out[addr] = set()
        
        # 迭代直到不动点
        changed = True
        while changed:
            changed = False
            
            # 逆序遍历
            for addr in reversed(list(self.basic_blocks.keys())):
                block = self.basic_blocks[addr]
                
                # live_out = U live_in(successors)
                new_out = set()
                for succ in block.successors:
                    if succ in self. live_in:
                        new_out |= self.live_in[succ]
                
                # live_in = use U (live_out - def)
                new_in = self.uses[addr] | (new_out - self. definitions[addr])
                
                if new_in != self.live_in[addr] or new_out != self.live_out[addr]:
                    changed = True
                    self.live_in[addr] = new_in
                    self.live_out[addr] = new_out
    
    def find_dead_code(self) -> List[Instruction]:
        """查找死代码"""
        dead_instructions = []
        
        for addr, block in self.basic_blocks.items():
            live = self.live_out. get(addr, set()).copy()
            
            # 反向遍历指令
            for instr in reversed(block.instructions):
                # 如果写入的变量不活跃且没有副作用
                if instr.writes and not any(w in live for w in instr.writes):
                    if not self._has_side_effects(instr):
                        dead_instructions.append(instr)
                
                # 更新活跃集
                for w in instr. writes:
                    live.discard(w)
                for r in instr. reads:
                    live.add(r)
        
        return dead_instructions
    
    def _has_side_effects(self, instr: Instruction) -> bool:
        """检查指令是否有副作用"""
        # 这些指令有副作用
        side_effect_mnemonics = [
            'call', 'int', 'syscall', 'sysenter',
            'push', 'pop', 'ret', 'jmp',
            'in', 'out', 'cli', 'sti',
            'stosb', 'stosw', 'stosd', 'movsb', 'movsw', 'movsd'
        ]
        
        return instr.mnemonic. lower() in side_effect_mnemonics


# ============================================================================
# 语义分析器
# ============================================================================

class SemanticAnalyzer:
    """语义分析器 - 理解代码意图"""
    
    # 常见函数模式
    FUNCTION_PATTERNS = {
        'string_copy': [
            ['mov', 'cmp', 'je', 'mov', 'inc', 'jmp'],  # 简单strcpy
            ['rep', 'movsb'],  # memcpy风格
        ],
        'string_length': [
            ['xor', 'mov', 'cmp', 'je', 'inc', 'jmp'],  # strlen
            ['repne', 'scasb'],
        ],
        'loop_counter': [
            ['mov', 'cmp', 'jge', 'inc', 'jmp'],  # for循环
            ['mov', 'dec', 'jnz'],  # countdown循环
        ],
        'memory_clear': [
            ['xor', 'rep', 'stosb'],  # memset(0)
            ['mov', 'rep', 'stosd'],
        ],
        'comparison': [
            ['cmp', 'je'],
            ['cmp', 'jne'],
            ['test', 'jz'],
            ['test', 'jnz'],
        ],
        'switch_table': [
            ['cmp', 'ja', 'jmp'],  # switch跳转表
        ],
    }
    
    # API功能分类
    API_CATEGORIES = {
        'file_io': ['CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 
                    'DeleteFile', 'MoveFile', 'CopyFile', 'fopen', 'fread', 'fwrite'],
        'network': ['socket', 'connect', 'send', 'recv', 'WSAStartup',
                   'InternetOpen', 'HttpOpenRequest', 'HttpSendRequest'],
        'process': ['CreateProcess', 'OpenProcess', 'TerminateProcess',
                   'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory'],
        'registry': ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegCreateKey'],
        'crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 
                  'CryptCreateHash', 'BCryptEncrypt'],
        'memory': ['malloc', 'free', 'HeapAlloc', 'HeapFree', 'VirtualAlloc'],
        'string': ['strcpy', 'strcmp', 'strlen', 'strcat', 'sprintf', 'memcpy', 'memset'],
        'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                      'NtQueryInformationProcess', 'GetTickCount'],
    }
    
    def __init__(self, functions: Dict[int, Function], imports: List[Dict] = None):
        self.functions = functions
        self.imports = imports or []
        self.api_map = self._build_api_map()
    
    def _build_api_map(self) -> Dict[str, str]:
        """构建API到类别的映射"""
        api_map = {}
        for category, apis in self.API_CATEGORIES.items():
            for api in apis: 
                api_map[api. lower()] = category
        return api_map
    
    def analyze_function_purpose(self, func: Function) -> Dict[str, Any]:
        """分析函数目的"""
        analysis = {
            'purpose': 'unknown',
            'patterns_matched': [],
            'api_calls': [],
            'api_categories': set(),
            'is_suspicious': False,
            'suspicion_reasons': [],
            'description': '',
        }
        
        # 收集指令序列
        mnemonics = []
        for bb in func.basic_blocks:
            for instr in bb.instructions:
                mnemonics.append(instr.mnemonic)
        
        # 匹配模式
        for pattern_name, patterns in self.FUNCTION_PATTERNS.items():
            for pattern in patterns:
                if self._match_pattern(mnemonics, pattern):
                    analysis['patterns_matched'].append(pattern_name)
        
        # 分析API调用
        for call_target in func.calls:
            api_name = self._resolve_api_name(call_target)
            if api_name:
                analysis['api_calls'].append(api_name)
                category = self.api_map.get(api_name.lower())
                if category: 
                    analysis['api_categories'].add(category)
        
        # 判断可疑性
        suspicious_categories = {'anti_debug', 'process', 'crypto'}
        if analysis['api_categories'] & suspicious_categories:
            analysis['is_suspicious'] = True
            analysis['suspicion_reasons']. append(
                f"使用了敏感API类别: {analysis['api_categories'] & suspicious_categories}"
            )
        
        # 生成描述
        analysis['description'] = self._generate_description(analysis)
        
        return analysis
    
    def _match_pattern(self, mnemonics:  List[str], pattern: List[str]) -> bool:
        """匹配指令模式"""
        if len(pattern) > len(mnemonics):
            return False
        
        pattern_str = ' '.join(pattern)
        mnemonic_str = ' '.join(mnemonics)
        
        return pattern_str in mnemonic_str
    
    def _resolve_api_name(self, address: int) -> Optional[str]:
        """解析API名称"""
        for imp in self.imports:
            if imp. get('address') == hex(address) or imp.get('address') == address:
                return imp. get('function', '')
        return None
    
    def _generate_description(self, analysis:  Dict) -> str:
        """生成函数描述"""
        parts = []
        
        if 'string_copy' in analysis['patterns_matched']: 
            parts.append("字符串复制操作")
        if 'string_length' in analysis['patterns_matched']:
            parts.append("字符串长度计算")
        if 'loop_counter' in analysis['patterns_matched']:
            parts.append("循环计数操作")
        if 'memory_clear' in analysis['patterns_matched']:
            parts.append("内存清零操作")
        
        if 'file_io' in analysis['api_categories']:
            parts. append("文件I/O操作")
        if 'network' in analysis['api_categories']: 
            parts.append("网络通信")
        if 'crypto' in analysis['api_categories']:
            parts.append("加密/解密操作")
        if 'registry' in analysis['api_categories']:
            parts.append("注册表操作")
        
        return "; ".join(parts) if parts else "未识别的功能"


# ============================================================================
# 补丁分析器
# ============================================================================

class PatchAnalyzer: 
    """补丁分析器 - 识别可修改点"""
    
    # NOP指令
    NOP_X86 = b'\x90'
    NOP_X64 = b'\x90'
    
    # 无条件跳转（短跳）
    JMP_SHORT = b'\xEB'
    
    def __init__(self, instructions: List[Instruction], engine: DisassemblyEngine):
        self.instructions = instructions
        self.engine = engine
        self. patch_points:  List[PatchPoint] = []
    
    def find_patch_points(self) -> List[PatchPoint]: 
        """查找所有可能的补丁点"""
        self.patch_points = []
        
        # 1. 条件跳转 - 可以修改条件或NOP掉
        self._find_conditional_jumps()
        
        # 2. 函数调用 - 可以NOP或重定向
        self._find_calls()
        
        # 3. 比较指令 - 可以修改比较值
        self._find_comparisons()
        
        # 4. 返回值 - 可以修改返回值
        self._find_returns()
        
        # 5. 字符串引用 - 可以修改字符串
        self._find_string_refs()
        
        # 6. 常量值 - 可以修改常量
        self._find_constants()
        
        return self.patch_points
    
    def _find_conditional_jumps(self):
        """查找条件跳转"""
        for instr in self. instructions:
            if instr.is_conditional:
                # 计算跳转距离
                if instr.branch_target:
                    distance = instr.branch_target - (instr.address + instr.size)
                else:
                    distance = 0
                
                patches = []
                
                # 方案1: NOP掉跳转（总是fall-through）
                patches.append({
                    'name': 'NOP跳转',
                    'bytes': self.NOP_X86 * instr.size,
                    'description': '移除条件跳转，总是执行后续代码'
                })
                
                # 方案2: 改为无条件跳转（总是跳转）
                if -128 <= distance <= 127:
                    patches.append({
                        'name':  '强制跳转',
                        'bytes': self.JMP_SHORT + bytes([distance & 0xFF]),
                        'description':  '改为无条件跳转，总是执行跳转'
                    })
                
                # 方案3: 反转条件
                inverted = self._invert_condition(instr.mnemonic)
                if inverted: 
                    assembled = self.engine. assemble(f"{inverted} 0x{instr. branch_target:x}", instr.address)
                    if assembled:
                        patches.append({
                            'name':  '反转条件',
                            'bytes': assembled,
                            'description':  f'反转条件:  {instr.mnemonic} -> {inverted}'
                        })
                
                patch = PatchPoint(
                    address=instr.address,
                    size=instr.size,
                    original_bytes=instr. bytes,
                    original_instruction=str(instr),
                    patch_type='conditional_jump',
                    description=f'条件跳转:  {instr.mnemonic}',
                    risk_level='MEDIUM',
                    suggested_patches=patches,
                    side_effects=['可能改变程序逻辑流程', '可能绕过检查']
                )
                
                self.patch_points.append(patch)
    
    def _invert_condition(self, mnemonic: str) -> Optional[str]:
        """反转条件"""
        inversions = {
            'je': 'jne', 'jne':  'je',
            'jz':  'jnz', 'jnz': 'jz',
            'ja': 'jbe', 'jbe': 'ja',
            'jb': 'jae', 'jae': 'jb',
            'jg': 'jle', 'jle': 'jg',
            'jl': 'jge', 'jge': 'jl',
            'js': 'jns', 'jns': 'js',
            'jo': 'jno', 'jno': 'jo',
        }
        return inversions.get(mnemonic. lower())
    
    def _find_calls(self):
        """查找函数调用"""
        for instr in self. instructions:
            if instr.is_call:
                patches = []
                
                # 方案1: NOP掉调用
                patches.append({
                    'name': 'NOP调用',
                    'bytes': self.NOP_X86 * instr.size,
                    'description': '移除函数调用'
                })
                
                # 方案2: 返回固定值（如果是关键检查函数）
                # ret_true:  mov eax, 1; ret
                ret_true = b'\xB8\x01\x00\x00\x00\xC3'
                # ret_false: xor eax, eax; ret
                ret_false = b'\x31\xC0\xC3'
                
                if instr.size >= 6:
                    patches.append({
                        'name': '返回TRUE',
                        'bytes': ret_true + self.NOP_X86 * (instr.size - 6),
                        'description': '替换调用，直接返回1(TRUE)'
                    })
                
                if instr. size >= 3:
                    patches.append({
                        'name': '返回FALSE',
                        'bytes':  ret_false + self.NOP_X86 * (instr.size - 3),
                        'description': '替换调用，直接返回0(FALSE)'
                    })
                
                patch = PatchPoint(
                    address=instr.address,
                    size=instr.size,
                    original_bytes=instr.bytes,
                    original_instruction=str(instr),
                    patch_type='call',
                    description=f'函数调用: {instr. op_str}',
                    risk_level='HIGH',
                    suggested_patches=patches,
                    side_effects=['移除功能', '可能导致程序不稳定', '可能绕过安全检查']
                )
                
                self.patch_points.append(patch)
    
    def _find_comparisons(self):
        """查找比较指令"""
        for i, instr in enumerate(self.instructions):
            if instr.mnemonic in ['cmp', 'test']: 
                patches = []
                
                # 尝试解析比较的立即数
                match = re.search(r'0x([0-9a-fA-F]+)|(\d+)', instr.op_str)
                if match: 
                    # 方案:  修改比较值
                    patches.append({
                        'name': '修改比较值为0',
                        'bytes': None,  # 需要具体分析
                        'description': '将比较的常量改为0'
                    })
                    patches.append({
                        'name': '修改比较值为1',
                        'bytes': None,
                        'description': '将比较的常量改为1'
                    })
                
                # 方案: NOP掉比较和后续跳转
                if i + 1 < len(self.instructions):
                    next_instr = self.instructions[i + 1]
                    if next_instr.is_conditional:
                        total_size = instr.size + next_instr.size
                        patches.append({
                            'name': 'NOP比较和跳转',
                            'bytes':  self.NOP_X86 * total_size,
                            'description': '移除整个条件检查'
                        })
                
                if patches:
                    patch = PatchPoint(
                        address=instr.address,
                        size=instr.size,
                        original_bytes=instr. bytes,
                        original_instruction=str(instr),
                        patch_type='comparison',
                        description=f'比较指令',
                        risk_level='MEDIUM',
                        suggested_patches=patches,
                        side_effects=['改变条件判断结果']
                    )
                    
                    self.patch_points.append(patch)
    
    def _find_returns(self):
        """查找返回指令"""
        for i, instr in enumerate(self.instructions):
            if instr.is_ret:
                # 查找前面的返回值设置
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev. mnemonic == 'mov' and 'eax' in prev.op_str. lower():
                        patches = []
                        
                        # 方案:  修改返回值
                        patches.append({
                            'name': '返回0',
                            'bytes': b'\x31\xC0',  # xor eax, eax
                            'description': '将返回值改为0'
                        })
                        patches.append({
                            'name': '返回1',
                            'bytes':  b'\xB8\x01\x00\x00\x00',  # mov eax, 1
                            'description': '将返回值改为1'
                        })
                        patches.append({
                            'name': '返回-1',
                            'bytes': b'\x83\xC8\xFF',  # or eax, -1
                            'description':  '将返回值改为-1'
                        })
                        
                        patch = PatchPoint(
                            address=prev.address,
                            size=prev. size,
                            original_bytes=prev.bytes,
                            original_instruction=str(prev),
                            patch_type='return_value',
                            description='返回值设置',
                            risk_level='MEDIUM',
                            suggested_patches=patches,
                            side_effects=['改变函数返回值', '影响调用者行为']
                        )
                        
                        self.patch_points.append(patch)
    
    def _find_string_refs(self):
        """查找字符串引用"""
        for instr in self.instructions:
            # 查找push立即数或mov到寄存器的大立即数（可能是字符串地址）
            if instr.mnemonic in ['push', 'mov', 'lea']:
                match = re.search(r'0x([4-7][0-9a-fA-F]{5,7})', instr.op_str)
                if match: 
                    addr = int(match. group(1), 16)
                    
                    patch = PatchPoint(
                        address=instr.address,
                        size=instr.size,
                        original_bytes=instr. bytes,
                        original_instruction=str(instr),
                        patch_type='string_ref',
                        description=f'可能的字符串引用: 0x{addr: x}',
                        risk_level='LOW',
                        suggested_patches=[{
                            'name':  '修改字符串地址',
                            'bytes': None,
                            'description': '将字符串引用指向其他位置'
                        }],
                        side_effects=['改变显示的文本', '可能导致崩溃']
                    )
                    
                    self.patch_points. append(patch)
    
    def _find_constants(self):
        """查找常量值"""
        for instr in self.instructions:
            if instr.mnemonic in ['mov', 'cmp', 'add', 'sub', 'and', 'or', 'xor']: 
                # 查找有意义的常量
                match = re. search(r'0x([0-9a-fA-F]+)', instr.op_str)
                if match: 
                    value = int(match. group(1), 16)
                    
                    # 过滤无意义的小值
                    if value > 0xFF and value < 0x7FFFFFFF:
                        patch = PatchPoint(
                            address=instr.address,
                            size=instr.size,
                            original_bytes=instr. bytes,
                            original_instruction=str(instr),
                            patch_type='constant',
                            description=f'常量值: 0x{value:x} ({value})',
                            risk_level='LOW',
                            suggested_patches=[{
                                'name':  '修改常量值',
                                'bytes': None,
                                'description': '修改此常量为其他值'
                            }],
                            side_effects=['改变计算结果', '可能影响程序逻辑']
                        )
                        
                        self. patch_points.append(patch)
    
    def generate_patch_script(self, patch:  PatchPoint, patch_index: int = 0) -> str:
        """生成补丁脚本"""
        if patch_index >= len(patch.suggested_patches):
            return ""
        
        suggested = patch.suggested_patches[patch_index]
        patch_bytes = suggested. get('bytes')
        
        if not patch_bytes:
            return f"# 需要手动实现:  {suggested['description']}"
        
        script = f"""# 补丁脚本
# 位置: 0x{patch.address:08x}
# 原始:  {patch.original_instruction}
# 补丁: {suggested['name']}
# 描述:  {suggested['description']}

import struct

def apply_patch(file_path, file_offset):
    original = {patch.original_bytes!r}
    patched = {patch_bytes!r}
    
    with open(file_path, 'r+b') as f:
        f.seek(file_offset)
        current = f.read(len(original))
        
        if current == original: 
            f.seek(file_offset)
            f.write(patched)
            print(f"补丁应用成功: 0x{{file_offset:x}}")
            return True
        else:
            print(f"原始字节不匹配，跳过")
            return False

# 使用方法: 
# apply_patch("target.exe", 0x{patch. address: x})  # 注意转换为文件偏移
"""
        return script


# ============================================================================
# AI团队 - 代码分析专家
# ============================================================================

class AICodeAnalyst(ABC):
    """AI代码分析师基类"""
    
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.findings:  List[Dict] = []
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """执行分析"""
        pass
    
    def _add_finding(self, category: str, severity: str, title: str, 
                     details: str, recommendation: str = ""):
        """添加发现"""
        self.findings.append({
            'analyst': self.name,
            'category':  category,
            'severity': severity,
            'title': title,
            'details': details,
            'recommendation': recommendation
        })


class LogicAnalyst(AICodeAnalyst):
    """逻辑分析师 - 理解代码逻辑流程"""
    
    def __init__(self):
        super().__init__("逻辑分析师", "理解和解释代码的控制流和数据流")
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'analyst': self.name,
            'analysis_type': 'logic_flow',
            'findings': [],
            'code_structure': {},
            'logic_summary': ''
        }
        
        functions = data.get('functions', {})
        basic_blocks = data. get('basic_blocks', {})
        
        # 分析每个函数的逻辑
        for addr, func in functions. items():
            func_analysis = self._analyze_function_logic(func)
            result['findings']. append(func_analysis)
        
        # 生成整体逻辑摘要
        result['code_structure'] = {
            'total_functions': len(functions),
            'total_blocks': len(basic_blocks),
            'entry_points': [addr for addr, bb in basic_blocks. items() if bb.is_entry],
            'exit_points': [addr for addr, bb in basic_blocks.items() if bb.is_exit],
        }
        
        # 检测关键逻辑模式
        patterns = self._detect_logic_patterns(data)
        result['logic_patterns'] = patterns
        
        result['logic_summary'] = self._generate_logic_summary(result)
        
        return result
    
    def _analyze_function_logic(self, func: Function) -> Dict:
        """分析单个函数的逻辑"""
        analysis = {
            'address': hex(func.address),
            'name': func.name,
            'block_count': len(func.basic_blocks),
            'call_count': len(func.calls),
            'logic_type': 'unknown',
            'description': ''
        }
        
        # 判断函数类型
        if len(func.basic_blocks) == 1:
            analysis['logic_type'] = 'linear'
            analysis['description'] = '简单线性函数，无分支'
        elif any(bb.loop_header for bb in func. basic_blocks):
            analysis['logic_type'] = 'loop'
            analysis['description'] = '包含循环结构'
        elif len(func.basic_blocks) > 5:
            analysis['logic_type'] = 'complex'
            analysis['description'] = f'复杂函数，包含{len(func.basic_blocks)}个基本块'
        else:
            analysis['logic_type'] = 'branching'
            analysis['description'] = '包含条件分支'
        
        return analysis
    
    def _detect_logic_patterns(self, data: Dict) -> List[Dict]:
        """检测逻辑模式"""
        patterns = []
        instructions = data.get('instructions', [])
        
        # 检测条件
        # 检测条件检查模式
        for i, instr in enumerate(instructions):
            if instr. mnemonic == 'cmp' and i + 1 < len(instructions):
                next_instr = instructions[i + 1]
                if next_instr.is_conditional: 
                    patterns.append({
                        'type': 'condition_check',
                        'address': hex(instr.address),
                        'pattern': f'{instr.mnemonic} {instr.op_str} -> {next_instr.mnemonic}',
                        'description': '条件检查后跳转'
                    })
        
        # 检测循环模式
        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['loop', 'loope', 'loopne']:
                patterns. append({
                    'type': 'loop',
                    'address': hex(instr.address),
                    'pattern': f'{instr.mnemonic} {instr.op_str}',
                    'description': '计数循环'
                })
            elif instr.is_conditional and instr.branch_target:
                if instr.branch_target < instr.address:
                    patterns.append({
                        'type': 'backward_branch',
                        'address': hex(instr.address),
                        'target': hex(instr.branch_target),
                        'description': '向后跳转（可能是循环）'
                    })
        
        # 检测函数调用链
        call_sequence = []
        for instr in instructions: 
            if instr. is_call:
                call_sequence.append({
                    'address': hex(instr.address),
                    'target': instr.op_str
                })
        
        if len(call_sequence) > 3:
            patterns. append({
                'type': 'call_chain',
                'calls': call_sequence[: 10],
                'description': f'函数调用链（{len(call_sequence)}个调用）'
            })
        
        return patterns
    
    def _generate_logic_summary(self, result: Dict) -> str:
        """生成逻辑摘要"""
        structure = result. get('code_structure', {})
        patterns = result.get('logic_patterns', [])
        
        summary_parts = []
        summary_parts.append(f"代码包含 {structure. get('total_functions', 0)} 个函数，"
                           f"{structure.get('total_blocks', 0)} 个基本块。")
        
        # 统计模式类型
        pattern_types = defaultdict(int)
        for p in patterns:
            pattern_types[p['type']] += 1
        
        if pattern_types: 
            summary_parts. append("检测到的逻辑模式：")
            for ptype, count in pattern_types.items():
                summary_parts.append(f"  - {ptype}: {count} 处")
        
        return "\n".join(summary_parts)


class SecurityAnalyst(AICodeAnalyst):
    """安全分析师 - 识别安全问题和可利用点"""
    
    def __init__(self):
        super().__init__("安全分析师", "识别安全漏洞和可利用的代码点")
        
        # 危险函数列表
        self. dangerous_functions = {
            'strcpy': '缓冲区溢出风险',
            'strcat': '缓冲区溢出风险',
            'sprintf': '格式化字符串漏洞',
            'gets': '严重缓冲区溢出',
            'scanf': '输入验证问题',
            'memcpy': '需检查长度参数',
            'memmove': '需检查长度参数',
        }
        
        # 安全检查函数
        self.security_functions = {
            'IsDebuggerPresent': '调试器检测',
            'CheckRemoteDebuggerPresent': '远程调试器检测',
            'NtQueryInformationProcess':  '进程信息查询（可能是反调试）',
            'GetTickCount': '时间检测（可能是反调试）',
            'QueryPerformanceCounter':  '性能计数器（可能是反调试）',
            'OutputDebugString': '调试输出检测',
        }
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        result = {
            'analyst':  self.name,
            'analysis_type': 'security',
            'vulnerabilities': [],
            'security_checks': [],
            'bypass_opportunities': [],
            'risk_assessment': {}
        }
        
        instructions = data.get('instructions', [])
        imports = data.get('imports', [])
        patch_points = data.get('patch_points', [])
        
        # 分析导入函数的安全性
        result['dangerous_imports'] = self._analyze_imports(imports)
        
        # 分析安全检查点
        result['security_checks'] = self._find_security_checks(instructions, imports)
        
        # 分析绕过机会
        result['bypass_opportunities'] = self._find_bypass_opportunities(
            instructions, patch_points, result['security_checks']
        )
        
        # 风险评估
        result['risk_assessment'] = self._assess_risk(result)
        
        return result
    
    def _analyze_imports(self, imports:  List[Dict]) -> List[Dict]:
        """分析危险导入"""
        dangerous = []
        
        for imp in imports: 
            func_name = imp. get('function', '')
            
            # 检查危险函数
            for dangerous_func, risk in self.dangerous_functions.items():
                if dangerous_func. lower() in func_name.lower():
                    dangerous.append({
                        'function': func_name,
                        'dll': imp.get('dll', ''),
                        'risk':  risk,
                        'severity': 'HIGH'
                    })
            
            # 检查安全相关函数
            for sec_func, purpose in self.security_functions.items():
                if sec_func.lower() in func_name.lower():
                    dangerous. append({
                        'function': func_name,
                        'dll': imp.get('dll', ''),
                        'purpose':  purpose,
                        'severity': 'INFO',
                        'is_security_check': True
                    })
        
        return dangerous
    
    def _find_security_checks(self, instructions: List[Instruction], 
                              imports: List[Dict]) -> List[Dict]:
        """查找安全检查点"""
        checks = []
        
        # 查找调用安全检查函数的位置
        for i, instr in enumerate(instructions):
            if instr.is_call: 
                # 检查是否调用了安全函数
                for sec_func in self.security_functions:
                    if sec_func. lower() in instr.op_str. lower():
                        # 查找后续的条件跳转
                        check = {
                            'address': hex(instr.address),
                            'function': sec_func,
                            'purpose': self. security_functions[sec_func],
                            'subsequent_check': None
                        }
                        
                        # 查找后续的test/cmp和跳转
                        for j in range(i + 1, min(i + 10, len(instructions))):
                            next_instr = instructions[j]
                            if next_instr.mnemonic in ['test', 'cmp']:
                                check['comparison'] = str(next_instr)
                            if next_instr.is_conditional: 
                                check['subsequent_check'] = {
                                    'address': hex(next_instr.address),
                                    'instruction': str(next_instr)
                                }
                                break
                        
                        checks.append(check)
        
        # 查找常见的检查模式
        for i, instr in enumerate(instructions):
            # 检测 cmp eax, 0 / test eax, eax 后跟条件跳转
            if instr.mnemonic in ['test', 'cmp']:
                if 'eax' in instr.op_str. lower() and i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr.is_conditional:
                        checks.append({
                            'address':  hex(instr. address),
                            'type': 'return_value_check',
                            'comparison': str(instr),
                            'jump':  str(next_instr),
                            'purpose': '返回值检查'
                        })
        
        return checks
    
    def _find_bypass_opportunities(self, instructions: List[Instruction],
                                   patch_points: List[PatchPoint],
                                   security_checks: List[Dict]) -> List[Dict]: 
        """查找绕过机会"""
        opportunities = []
        
        # 基于安全检查找绕过点
        for check in security_checks: 
            if check. get('subsequent_check'):
                addr_str = check['subsequent_check']. get('address', '0x0')
                addr = int(addr_str, 16)
                
                opportunity = {
                    'target': check. get('function', check. get('type', 'unknown')),
                    'check_address': check['address'],
                    'bypass_address': addr_str,
                    'method': 'NOP条件跳转或反转条件',
                    'difficulty': 'EASY',
                    'description': f"可以通过修改 {addr_str} 处的跳转来绕过检查"
                }
                opportunities.append(opportunity)
        
        # 基于补丁点分析
        for patch in patch_points:
            if patch.patch_type == 'conditional_jump':
                opportunities.append({
                    'target': '条件检查',
                    'check_address':  hex(patch.address),
                    'bypass_address': hex(patch.address),
                    'method': patch.suggested_patches[0]['name'] if patch.suggested_patches else 'NOP',
                    'difficulty': 'EASY',
                    'description': patch.description
                })
            elif patch.patch_type == 'call': 
                opportunities.append({
                    'target': '函数调用',
                    'check_address': hex(patch.address),
                    'bypass_address': hex(patch.address),
                    'method': 'NOP调用或修改返回值',
                    'difficulty': 'MEDIUM',
                    'description': patch.description
                })
        
        return opportunities
    
    def _assess_risk(self, result: Dict) -> Dict:
        """风险评估"""
        dangerous_count = len(result.get('dangerous_imports', []))
        security_count = len(result. get('security_checks', []))
        bypass_count = len(result.get('bypass_opportunities', []))
        
        risk_score = 0
        risk_score += dangerous_count * 2
        risk_score += bypass_count
        
        if risk_score >= 10:
            risk_level = 'CRITICAL'
        elif risk_score >= 5:
            risk_level = 'HIGH'
        elif risk_score >= 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'dangerous_function_count': dangerous_count,
            'security_check_count': security_count,
            'bypass_opportunity_count': bypass_count,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        if risk_level == 'CRITICAL': 
            return "发现多个高危点，建议深入分析每个安全检查的绕过可能性"
        elif risk_level == 'HIGH': 
            return "存在明显的安全检查，可以尝试补丁绕过"
        elif risk_level == 'MEDIUM': 
            return "存在一些检查点，需要进一步分析"
        else: 
            return "安全检查较少，可能不是主要保护逻辑"


class PatchExpert(AICodeAnalyst):
    """补丁专家 - 提供修改建议"""
    
    def __init__(self):
        super().__init__("补丁专家", "分析可修改点并提供具体补丁方案")
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'analyst': self.name,
            'analysis_type': 'patching',
            'patch_recommendations': [],
            'modification_plan': [],
            'risk_analysis': {}
        }
        
        patch_points = data. get('patch_points', [])
        functions = data.get('functions', {})
        security_analysis = data.get('security_analysis', {})
        
        # 分类补丁点
        categorized = self._categorize_patches(patch_points)
        result['categorized_patches'] = categorized
        
        # 生成修改建议
        result['patch_recommendations'] = self._generate_recommendations(
            patch_points, security_analysis
        )
        
        # 生成修改计划
        result['modification_plan'] = self._create_modification_plan(
            result['patch_recommendations']
        )
        
        # 风险分析
        result['risk_analysis'] = self._analyze_patch_risks(patch_points)
        
        return result
    
    def _categorize_patches(self, patch_points: List[PatchPoint]) -> Dict[str, List]: 
        """分类补丁点"""
        categories = defaultdict(list)
        
        for patch in patch_points: 
            categories[patch.patch_type]. append({
                'address':  hex(patch.address),
                'description': patch.description,
                'risk_level': patch. risk_level,
                'patch_count': len(patch.suggested_patches)
            })
        
        return dict(categories)
    
    def _generate_recommendations(self, patch_points: List[PatchPoint],
                                  security_analysis: Dict) -> List[Dict]:
        """生成补丁建议"""
        recommendations = []
        
        bypass_opportunities = security_analysis.get('bypass_opportunities', [])
        bypass_addresses = {opp. get('bypass_address') for opp in bypass_opportunities}
        
        for patch in patch_points: 
            addr_hex = hex(patch. address)
            
            priority = 'LOW'
            if addr_hex in bypass_addresses:
                priority = 'HIGH'
            elif patch. patch_type in ['conditional_jump', 'call']:
                priority = 'MEDIUM'
            
            rec = {
                'address': addr_hex,
                'type': patch.patch_type,
                'priority':  priority,
                'original':  patch.original_instruction,
                'suggestions': [],
                'side_effects': patch.side_effects
            }
            
            for suggested in patch.suggested_patches:
                if suggested. get('bytes'):
                    rec['suggestions'].append({
                        'name': suggested['name'],
                        'description': suggested['description'],
                        'bytes': suggested['bytes']. hex(),
                        'reversible': True
                    })
            
            if rec['suggestions']: 
                recommendations.append(rec)
        
        # 按优先级排序
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x:  priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def _create_modification_plan(self, recommendations: List[Dict]) -> List[Dict]:
        """创建修改计划"""
        plan = []
        
        high_priority = [r for r in recommendations if r['priority'] == 'HIGH']
        
        for i, rec in enumerate(high_priority[: 5], 1):
            step = {
                'step': i,
                'action': f"修改 {rec['address']} 处的 {rec['type']}",
                'target': rec['address'],
                'original': rec['original'],
                'suggested_patch': rec['suggestions'][0] if rec['suggestions'] else None,
                'expected_effect': rec['suggestions'][0]['description'] if rec['suggestions'] else '未知',
                'verification':  '运行程序验证修改效果'
            }
            plan.append(step)
        
        return plan
    
    def _analyze_patch_risks(self, patch_points: List[PatchPoint]) -> Dict:
        """分析补丁风险"""
        risk_counts = defaultdict(int)
        for patch in patch_points:
            risk_counts[patch.risk_level] += 1
        
        total = len(patch_points)
        
        return {
            'total_patches': total,
            'by_risk_level':  dict(risk_counts),
            'high_risk_percentage': (risk_counts.get('HIGH', 0) + 
                                    risk_counts.get('CRITICAL', 0)) / total * 100 if total > 0 else 0,
            'recommendation':  self._get_risk_recommendation(risk_counts)
        }
    
    def _get_risk_recommendation(self, risk_counts: Dict) -> str:
        high_risk = risk_counts.get('HIGH', 0) + risk_counts. get('CRITICAL', 0)
        if high_risk > 5:
            return "存在多个高风险修改点，建议在虚拟机中测试"
        elif high_risk > 0:
            return "建议先备份原文件再进行修改"
        else:
            return "风险较低，可以尝试修改"


class ReverseEngineer(AICodeAnalyst):
    """逆向工程师 - 深度代码理解"""
    
    def __init__(self):
        super().__init__("逆向工程师", "深度分析代码结构和算法")
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        result = {
            'analyst': self.name,
            'analysis_type':  'reverse_engineering',
            'code_understanding': {},
            'algorithms_detected': [],
            'data_structures':  [],
            'decompilation_hints': []
        }
        
        instructions = data.get('instructions', [])
        functions = data.get('functions', {})
        basic_blocks = data. get('basic_blocks', {})
        
        # 分析代码结构
        result['code_understanding'] = self._understand_code_structure(
            instructions, functions, basic_blocks
        )
        
        # 检测算法模式
        result['algorithms_detected'] = self._detect_algorithms(instructions)
        
        # 识别数据结构
        result['data_structures'] = self._identify_data_structures(instructions)
        
        # 生成伪代码提示
        result['decompilation_hints'] = self._generate_decompilation_hints(functions)
        
        return result
    
    def _understand_code_structure(self, instructions: List[Instruction],
                                   functions: Dict[int, Function],
                                   basic_blocks: Dict[int, BasicBlock]) -> Dict:
        """理解代码结构"""
        structure = {
            'instruction_count': len(instructions),
            'function_count': len(functions),
            'block_count':  len(basic_blocks),
            'instruction_distribution': {},
            'control_flow_complexity': 'unknown'
        }
        
        # 指令类型分布
        type_counts = defaultdict(int)
        for instr in instructions:
            type_counts[instr. instruction_type. name] += 1
        
        structure['instruction_distribution'] = dict(type_counts)
        
        # 计算控制流复杂度
        branch_count = sum(1 for i in instructions if i. is_conditional)
        call_count = sum(1 for i in instructions if i.is_call)
        
        complexity_score = branch_count + call_count * 0.5
        if complexity_score > 50:
            structure['control_flow_complexity'] = 'HIGH'
        elif complexity_score > 20:
            structure['control_flow_complexity'] = 'MEDIUM'
        else:
            structure['control_flow_complexity'] = 'LOW'
        
        structure['metrics'] = {
            'branch_count': branch_count,
            'call_count': call_count,
            'complexity_score': complexity_score
        }
        
        return structure
    
    def _detect_algorithms(self, instructions: List[Instruction]) -> List[Dict]:
        """检测算法模式"""
        algorithms = []
        
        # 检测XOR循环（可能是加密）
        xor_count = 0
        loop_detected = False
        for i, instr in enumerate(instructions):
            if instr.mnemonic == 'xor' and 'eax' not in instr.op_str. lower():
                xor_count += 1
            if instr.mnemonic in ['loop', 'loope', 'loopne']:
                loop_detected = True
            if instr.is_conditional and instr.branch_target and instr.branch_target < instr.address:
                loop_detected = True
        
        if xor_count > 5 and loop_detected:
            algorithms.append({
                'name': 'XOR加密/解密',
                'confidence': 'HIGH' if xor_count > 10 else 'MEDIUM',
                'indicators': f'{xor_count}个XOR操作，存在循环',
                'description':  '可能是简单的XOR加密算法'
            })
        
        # 检测移位操作（可能是哈希或加密）
        shift_ops = sum(1 for i in instructions if i. mnemonic in ['shl', 'shr', 'rol', 'ror', 'sar'])
        if shift_ops > 10:
            algorithms. append({
                'name': '位操作密集算法',
                'confidence': 'MEDIUM',
                'indicators': f'{shift_ops}个移位操作',
                'description': '可能是哈希函数或复杂加密'
            })
        
        # 检测字符串操作
        string_ops = sum(1 for i in instructions if i.instruction_type == InstructionType.STRING)
        if string_ops > 5:
            algorithms. append({
                'name': '字符串处理',
                'confidence':  'HIGH',
                'indicators':  f'{string_ops}个字符串操作',
                'description': '字符串复制/比较/搜索'
            })
        
        # 检测数学运算（可能是校验和）
        math_ops = sum(1 for i in instructions 
                      if i.mnemonic in ['add', 'adc', 'mul', 'imul', 'div', 'idiv'])
        if math_ops > 20:
            algorithms. append({
                'name': '数学计算',
                'confidence': 'MEDIUM',
                'indicators': f'{math_ops}个数学运算',
                'description': '可能是校验和或数值计算'
            })
        
        return algorithms
    
    def _identify_data_structures(self, instructions: List[Instruction]) -> List[Dict]:
        """识别数据结构"""
        structures = []
        
        # 检测数组访问模式
        array_patterns = 0
        for instr in instructions:
            # 类似 [reg + reg*scale] 或 [reg + offset]
            if re.search(r'\[.*\+.*\*[1248]\]', instr. op_str):
                array_patterns += 1
            elif re.search(r'\[.*\+\s*0x[0-9a-f]+\]', instr.op_str):
                array_patterns += 1
        
        if array_patterns > 5:
            structures. append({
                'type': 'array',
                'confidence': 'HIGH' if array_patterns > 15 else 'MEDIUM',
                'indicators': f'{array_patterns}个数组访问模式',
                'description': '检测到数组或结构体数组访问'
            })
        
        # 检测链表操作（指针跟随模式）
        deref_chain = 0
        for i, instr in enumerate(instructions):
            if instr.mnemonic == 'mov' and '[' in instr. op_str: 
                if i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr.mnemonic == 'mov' and '[' in next_instr.op_str:
                        deref_chain += 1
        
        if deref_chain > 3:
            structures. append({
                'type': 'linked_structure',
                'confidence': 'MEDIUM',
                'indicators': f'{deref_chain}个连续指针解引用',
                'description': '可能是链表或树结构遍历'
            })
        
        # 检测栈帧结构（局部变量）
        stack_access = 0
        for instr in instructions: 
            if re.search(r'\[e? [sb]p[+-]', instr.op_str):
                stack_access += 1
        
        if stack_access > 10:
            structures. append({
                'type': 'local_variables',
                'confidence': 'HIGH',
                'indicators':  f'{stack_access}个栈访问',
                'description': '函数使用多个局部变量'
            })
        
        return structures
    
    def _generate_decompilation_hints(self, functions: Dict[int, Function]) -> List[Dict]: 
        """生成反编译提示"""
        hints = []
        
        for addr, func in list(functions.items())[:10]:  # 限制数量
            hint = {
                'function': func.name,
                'address':  hex(func.address),
                'estimated_complexity': 'unknown',
                'pseudocode_structure': [],
                'variable_hints': []
            }
            
            # 分析基本块生成伪代码结构
            if func.basic_blocks:
                has_loop = any(bb.loop_header for bb in func. basic_blocks)
                has_branch = len(func.basic_blocks) > 1
                
                if has_loop: 
                    hint['pseudocode_structure']. append('包含循环结构 (while/for)')
                if has_branch: 
                    hint['pseudocode_structure']. append('包含条件分支 (if/else)')
                if len(func.calls) > 0:
                    hint['pseudocode_structure'].append(f'调用 {len(func. calls)} 个其他函数')
                
                # 复杂度估计
                bb_count = len(func.basic_blocks)
                if bb_count > 10:
                    hint['estimated_complexity'] = 'HIGH'
                elif bb_count > 3:
                    hint['estimated_complexity'] = 'MEDIUM'
                else: 
                    hint['estimated_complexity'] = 'LOW'
            
            hints.append(hint)
        
        return hints


class BehaviorAnalyst(AICodeAnalyst):
    """行为分析师 - 分析程序运行时行为"""
    
    def __init__(self):
        super().__init__("行为分析师", "预测和分析程序运行时行为")
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        result = {
            'analyst': self.name,
            'analysis_type':  'behavior',
            'predicted_behaviors': [],
            'api_usage_analysis': {},
            'suspicious_behaviors': [],
            'behavior_timeline': []
        }
        
        instructions = data.get('instructions', [])
        imports = data.get('imports', [])
        functions = data. get('functions', {})
        
        # 分析API使用
        result['api_usage_analysis'] = self._analyze_api_usage(imports)
        
        # 预测行为
        result['predicted_behaviors'] = self._predict_behaviors(imports, instructions)
        
        # 识别可疑行为
        result['suspicious_behaviors'] = self._identify_suspicious(imports, instructions)
        
        # 生成行为时间线
        result['behavior_timeline'] = self._create_behavior_timeline(
            instructions, imports, functions
        )
        
        return result
    
    def _analyze_api_usage(self, imports: List[Dict]) -> Dict:
        """分析API使用模式"""
        categories = defaultdict(list)
        
        api_categories = {
            'file':  ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'FindFirstFile'],
            'network':  ['socket', 'connect', 'send', 'recv', 'WSA', 'Internet', 'Http'],
            'process': ['CreateProcess', 'OpenProcess', 'VirtualAlloc', 'WriteProcessMemory'],
            'registry':  ['RegOpen', 'RegCreate', 'RegSet', 'RegQuery', 'RegDelete'],
            'crypto': ['Crypt', 'BCrypt', 'Hash'],
            'ui': ['MessageBox', 'CreateWindow', 'ShowWindow', 'GetDlgItem'],
            'memory': ['malloc', 'free', 'HeapAlloc', 'VirtualAlloc', 'GlobalAlloc'],
            'thread': ['CreateThread', 'ExitThread', 'WaitForSingleObject', 'SetEvent'],
        }
        
        for imp in imports: 
            func = imp.get('function', '')
            for category, keywords in api_categories. items():
                if any(kw. lower() in func.lower() for kw in keywords):
                    categories[category]. append(func)
                    break
        
        return {
            'categories': dict(categories),
            'primary_functionality': max(categories.keys(), 
                                        key=lambda k: len(categories[k])) if categories else 'unknown',
            'api_diversity': len(categories),
            'total_apis': len(imports)
        }
    
    def _predict_behaviors(self, imports: List[Dict], 
                          instructions: List[Instruction]) -> List[Dict]:
        """预测程序行为"""
        behaviors = []
        import_names = [imp.get('function', '').lower() for imp in imports]
        import_text = ' '.join(import_names)
        
        # 文件操作
        if any(x in import_text for x in ['createfile', 'writefile', 'deletefile']):
            behaviors. append({
                'type': '文件操作',
                'confidence':  'HIGH',
                'description': '程序会创建、修改或删除文件',
                'indicators': ['CreateFile', 'WriteFile', 'DeleteFile']
            })
        
        # 网络通信
        if any(x in import_text for x in ['socket', 'connect', 'wsastartup', 'internetopen']):
            behaviors.append({
                'type': '网络通信',
                'confidence': 'HIGH',
                'description': '程序会进行网络连接',
                'indicators':  ['socket', 'connect', 'send', 'recv']
            })
        
        # 进程操作
        if any(x in import_text for x in ['createprocess', 'openprocess', 'writeprocessmemory']):
            behaviors. append({
                'type': '进程操作',
                'confidence': 'HIGH',
                'description': '程序会创建或操作其他进程',
                'indicators': ['CreateProcess', 'OpenProcess']
            })
        
        # 注册表操作
        if any(x in import_text for x in ['regopen', 'regset', 'regcreate']):
            behaviors. append({
                'type': '注册表修改',
                'confidence': 'HIGH',
                'description': '程序会修改Windows注册表',
                'indicators': ['RegSetValue', 'RegCreateKey']
            })
        
        # 加密操作
        if any(x in import_text for x in ['crypt', 'bcrypt', 'hash']):
            behaviors.append({
                'type': '加密/解密',
                'confidence': 'HIGH',
                'description': '程序使用加密功能',
                'indicators': ['CryptEncrypt', 'CryptDecrypt']
            })
        
        # 屏幕/UI操作
        if any(x in import_text for x in ['messagebox', 'createwindow', 'getdc', 'bitblt']):
            behaviors.append({
                'type':  'UI交互',
                'confidence': 'HIGH',
                'description': '程序有用户界面',
                'indicators':  ['MessageBox', 'CreateWindow']
            })
        
        return behaviors
    
    def _identify_suspicious(self, imports:  List[Dict], 
                            instructions: List[Instruction]) -> List[Dict]:
        """识别可疑行为"""
        suspicious = []
        import_names = [imp.get('function', '').lower() for imp in imports]
        import_text = ' '.join(import_names)
        
        # 反调试
        anti_debug_apis = ['isdebuggerpresent', 'checkremotedebuggerpresent', 
                          'ntqueryinformationprocess', 'outputdebugstring']
        found_antidebug = [api for api in anti_debug_apis if api in import_text]
        if found_antidebug:
            suspicious.append({
                'type': '反调试',
                'severity': 'MEDIUM',
                'apis': found_antidebug,
                'description': '程序包含反调试检测',
                'bypass_suggestion': '修改检测函数返回值或NOP掉检测代码'
            })
        
        # 代码注入
        injection_apis = ['virtualallocex', 'writeprocessmemory', 'createremotethread',
                         'ntunmapviewofsection', 'rtlcreateprocessparameters']
        found_injection = [api for api in injection_apis if api in import_text]
        if len(found_injection) >= 2:
            suspicious.append({
                'type': '代码注入',
                'severity':  'HIGH',
                'apis': found_injection,
                'description': '程序可能进行代码注入',
                'bypass_suggestion': 'NOP掉注入相关调用'
            })
        
        # 键盘/鼠标钩子
        hook_apis = ['setwindowshookex', 'getasynckeystate', 'getkeystate', 'getkeyboardstate']
        found_hooks = [api for api in hook_apis if api in import_text]
        if found_hooks:
            suspicious.append({
                'type': '键盘监控',
                'severity': 'HIGH',
                'apis': found_hooks,
                'description':  '程序可能记录键盘输入',
                'bypass_suggestion': 'NOP掉钩子安装代码'
            })
        
        # 服务操作
        service_apis = ['createservice', 'openservice', 'startservice', 'controlservice']
        found_service = [api for api in service_apis if api in import_text]
        if found_service:
            suspicious.append({
                'type': '服务操作',
                'severity':  'MEDIUM',
                'apis': found_service,
                'description': '程序操作Windows服务',
                'bypass_suggestion':  '检查服务创建/启动逻辑'
            })
        
        return suspicious
    
    def _create_behavior_timeline(self, instructions: List[Instruction],
                                  imports: List[Dict],
                                  functions: Dict[int, Function]) -> List[Dict]:
        """创建行为时间线"""
        timeline = []
        
        # 基于调用顺序创建时间线
        call_sequence = []
        for instr in instructions: 
            if instr. is_call:
                call_sequence.append({
                    'address': hex(instr.address),
                    'target': instr.op_str
                })
        
        # 简化时间线（只显示前20个）
        for i, call in enumerate(call_sequence[:20]):
            timeline.append({
                'order': i + 1,
                'address': call['address'],
                'action': f"调用 {call['target']}",
                'significance': 'NORMAL'
            })
        
        return timeline


# ============================================================================
# AI团队管理器
# ============================================================================

class AITeamManager:
    """AI团队管理器"""
    
    def __init__(self):
        self.analysts = {
            'logic':  LogicAnalyst(),
            'security': SecurityAnalyst(),
            'patch':  PatchExpert(),
            'reverse': ReverseEngineer(),
            'behavior': BehaviorAnalyst()
        }
        self.analysis_results = {}
    
    def run_full_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        """运行完整的AI团队分析"""
        print("\n" + "="*70)
        print("🤖 AI团队分析开始")
        print("="*70)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'team_analysis': {},
            'consensus': {},
            'recommendations': []
        }
        
        # 逐个运行分析师
        for name, analyst in self. analysts.items():
            print(f"\n[*] {analyst.name} 正在分析...")
            try:
                analysis = analyst.analyze(data)
                results['team_analysis'][name] = analysis
                print(f"    ✓ {analyst.name} 完成")
            except Exception as e: 
                print(f"    ✗ {analyst.name} 失败:  {e}")
                results['team_analysis'][name] = {'error': str(e)}
        
        # 将安全分析结果传递给补丁专家
        if 'security' in results['team_analysis']:
            data['security_analysis'] = results['team_analysis']['security']
            results['team_analysis']['patch'] = self. analysts['patch'].analyze(data)
        
        # 生成共识
        results['consensus'] = self._build_consensus(results['team_analysis'])
        
        # 生成最终建议
        results['recommendations'] = self._generate_recommendations(results)
        
        self.analysis_results = results
        return results
    
    def _build_consensus(self, team_analysis: Dict) -> Dict:
        """建立团队共识"""
        consensus = {
            'overall_assessment': '',
            'key_findings': [],
            'priority_targets': [],
            'risk_level': 'UNKNOWN'
        }
        
        # 收集所有发现
        all_findings = []
        
        # 从安全分析收集
        security = team_analysis.get('security', {})
        if security. get('bypass_opportunities'):
            for opp in security['bypass_opportunities'][:5]: 
                all_findings. append({
                    'source': '安全分析师',
                    'finding': f"绕过机会:  {opp. get('target', 'unknown')} @ {opp.get('bypass_address', 'N/A')}",
                    'priority': 'HIGH'
                })
        
        if security.get('suspicious_behaviors'):
            for behavior in security['suspicious_behaviors']: 
                all_findings.append({
                    'source': '安全分析师',
                    'finding': f"可疑行为:  {behavior.get('type', 'unknown')}",
                    'priority': behavior.get('severity', 'MEDIUM')
                })
        
        # 从逆向分析收集
        reverse = team_analysis.get('reverse', {})
        if reverse.get('algorithms_detected'):
            for algo in reverse['algorithms_detected']: 
                all_findings.append({
                    'source': '逆向工程师',
                    'finding': f"检测到算法: {algo. get('name', 'unknown')}",
                    'priority': 'MEDIUM'
                })
        
        # 从行为分析收集
        behavior = team_analysis.get('behavior', {})
        if behavior.get('suspicious_behaviors'):
            for sus in behavior['suspicious_behaviors']:
                all_findings.append({
                    'source':  '行为分析师',
                    'finding': f"可疑行为: {sus.get('type', 'unknown')}",
                    'priority':  sus.get('severity', 'MEDIUM')
                })
        
        consensus['key_findings'] = all_findings[: 15]
        
        # 确定优先级目标
        patch = team_analysis.get('patch', {})
        if patch. get('modification_plan'):
            for step in patch['modification_plan'][:5]:
                consensus['priority_targets'].append({
                    'address': step. get('target', 'N/A'),
                    'action': step.get('action', ''),
                    'expected_effect': step.get('expected_effect', '')
                })
        
        # 计算整体风险级别
        risk = security.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        consensus['risk_level'] = risk
        
        # 生成整体评估
        high_findings = sum(1 for f in all_findings if f['priority'] == 'HIGH')
        consensus['overall_assessment'] = self._generate_assessment(
            high_findings, len(consensus['priority_targets']), risk
        )
        
        return consensus
    
    def _generate_assessment(self, high_findings: int, targets: int, risk:  str) -> str:
        """生成整体评估"""
        if risk == 'CRITICAL' or high_findings > 5:
            return "程序包含多个高优先级修改点，建议按计划逐步修改并测试"
        elif risk == 'HIGH' or high_findings > 2:
            return "发现若干可修改点，可以尝试绕过主要保护机制"
        elif targets > 0:
            return "存在一些可修改点，风险较低"
        else: 
            return "未发现明显的修改机会，可能需要更深入的分析"
    
    def _generate_recommendations(self, results: Dict) -> List[Dict]:
        """生成最终建议"""
        recommendations = []
        
        consensus = results.get('consensus', {})
        team_analysis = results. get('team_analysis', {})
        
        # 基于优先级目标生成建议
        for target in consensus. get('priority_targets', [])[:3]:
            recommendations.append({
                'priority': 1,
                'type': 'patch',
                'action':  target. get('action', ''),
                'target': target.get('address', ''),
                'expected_result': target.get('expected_effect', ''),
                'risk':  'MEDIUM'
            })
        
        # 基于可疑行为生成建议
        behavior = team_analysis. get('behavior', {})
        for sus in behavior.get('suspicious_behaviors', [])[:2]:
            recommendations. append({
                'priority': 2,
                'type':  'investigate',
                'action': f"调查 {sus.get('type', '')} 相关代码",
                'target': ', '. join(sus. get('apis', [])[:3]),
                'expected_result': sus. get('bypass_suggestion', ''),
                'risk':  sus.get('severity', 'MEDIUM')
            })
          # 排序
        recommendations. sort(key=lambda x: x['priority'])
        
        return recommendations
    
    def generate_report(self, output_path: str = None, analyzer_data: Dict = None) -> str:
        """生成分析报告"""
        if not self.analysis_results:
            return "没有分析结果"
        
        results = self.analysis_results
        
        # 设置默认的分析器数据
        if analyzer_data is None:
            analyzer_data = {}
        
        report = f"""# 🤖 AI团队反汇编分析报告

**生成时间**:  {results. get('timestamp', 'N/A')}

---

## 📊 团队共识

**整体评估**: {results['consensus']. get('overall_assessment', 'N/A')}

**风险级别**: {results['consensus'].get('risk_level', 'UNKNOWN')}

### 关键发现

| 来源 | 发现 | 优先级 |
|------|------|--------|
"""
        
        for finding in results['consensus']. get('key_findings', [])[:10]:
            report += f"| {finding['source']} | {finding['finding']} | {finding['priority']} |\n"
        
        report += f"""
### 优先修改目标

| 地址 | 操作 | 预期效果 |
|------|------|----------|
"""
        
        for target in results['consensus'].get('priority_targets', []):
            report += f"| {target['address']} | {target['action']} | {target['expected_effect']} |\n"
        
        report += f"""
---

## 🔧 修改建议

"""
        
        for i, rec in enumerate(results. get('recommendations', []), 1):
            report += f"""### 建议 {i}:  {rec['action']}

- **目标**: {rec['target']}
- **预期结果**: {rec['expected_result']}
- **风险**: {rec['risk']}

"""
        
        # 各分析师详细报告
        report += """
---

## 📋 详细分析报告

"""
        
        # 安全分析
        security = results['team_analysis'].get('security', {})
        if security: 
            report += f"""### 🔒 安全分析

**危险导入**: {len(security.get('dangerous_imports', []))} 个
**安全检查点**: {len(security.get('security_checks', []))} 个
**绕过机会**:  {len(security. get('bypass_opportunities', []))} 个

"""
            for opp in security. get('bypass_opportunities', [])[:5]:
                report += f"- **{opp.get('target', '')}** @ {opp.get('bypass_address', '')} - {opp.get('method', '')}\n"
        
        # 行为分析
        behavior = results['team_analysis'].get('behavior', {})
        if behavior: 
            report += f"""
### 🎯 行为分析

**预测行为**:
"""
            for b in behavior.get('predicted_behaviors', []):
                report += f"- {b.get('type', '')}: {b.get('description', '')}\n"
            
            if behavior.get('suspicious_behaviors'):
                report += f"""
**可疑行为**: 
"""
                for s in behavior['suspicious_behaviors']:
                    report += f"- ⚠️ **{s.get('type', '')}** ({s.get('severity', '')}): {s.get('description', '')}\n"
        
        # 逆向分析
        reverse = results['team_analysis'].get('reverse', {})
        if reverse: 
            report += f"""
### 🔍 逆向分析

**代码复杂度**: {reverse.get('code_understanding', {}).get('control_flow_complexity', 'N/A')}

**检测到的算法**:
"""
            for algo in reverse. get('algorithms_detected', []):
                report += f"- {algo.get('name', '')}: {algo.get('description', '')}\n"
        
        report += f"""
---

## 📝 补丁脚本示例

```python
# 自动生成的补丁脚本
# 警告: 请在虚拟机中测试

def apply_patches(file_path):
    patches = [
"""
        # 生成补丁代码
        patch_analysis = results['team_analysis']. get('patch', {})
        for rec in patch_analysis. get('patch_recommendations', [])[:3]:
            if rec. get('suggestions'):
                sugg = rec['suggestions'][0]
                report += f"""        {{
            'address':  '{rec['address']}',
            'original':  '{rec['original'][: 30]}...',
            'patch_bytes': bytes.fromhex('{sugg. get('bytes', '')}'),
            'description': '{sugg. get('description', '')}'
        }},
"""
        report += f"""    ]
    
    with open(file_path, 'r+b') as f:
        for patch in patches: 
            # 注意: 需要将虚拟地址转换为文件偏移
            # f.seek(patch['address'])
            # f. write(patch['patch_bytes'])
            print(f"应用补丁:  {{{{patch['description']}}}}")
"""
        
        # 生成时间戳用于文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_path:
            os.makedirs(output_path, exist_ok=True)
            report_path = os.path.join(output_path, f"report_{timestamp}.md")
            json_path = os.path.join(output_path, f"analysis_{timestamp}.json")
        else:
            report_path = f"report_{timestamp}.md"
            json_path = f"analysis_{timestamp}.json"
          # 保存Markdown报告
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n[*] 报告已保存: {report_path}")
        
        # 保存JSON数据（仅当有分析器数据时）
        if analyzer_data:
            json_data = {
                'timestamp': timestamp,
                'file_path': analyzer_data.get('file_path', 'N/A'),
                'file_hash': analyzer_data.get('file_hash', 'N/A'),
                'statistics': {
                    'instructions': len(analyzer_data.get('instructions', [])),
                    'basic_blocks': len(analyzer_data.get('basic_blocks', {})),
                    'functions': len(analyzer_data.get('functions', {})),
                    'imports': len(analyzer_data.get('imports', [])),
                    'exports': len(analyzer_data.get('exports', [])),
                    'patch_points': len(analyzer_data.get('patch_points', []))
                },
                'imports': analyzer_data.get('imports', []),
                'exports': analyzer_data.get('exports', []),
                'functions': [
                    {
                        'address': hex(addr),
                        'name': func.name,
                        'size': func.size,
                        'blocks': len(func.basic_blocks),
                        'calls': [hex(c) for c in func.calls],
                        'analysis': func.ai_analysis
                    }
                    for addr, func in list(analyzer_data.get('functions', {}).items())[:50]
                ],
                'patch_points': [
                    {
                        'address': hex(pp.address),
                        'type': pp.patch_type,
                        'original': pp.original_instruction,
                        'risk_level': pp.risk_level,
                        'description': pp.description,
                        'suggestions': [
                            {
                                'name': s['name'],
                                'description': s['description'],
                                'bytes': s['bytes'].hex() if s.get('bytes') else None
                            }
                            for s in pp.suggested_patches
                        ]
                    }
                    for pp in analyzer_data.get('patch_points', [])[:100]
                ],
                'ai_consensus': self.analysis_results.get('consensus', {})
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"\n[*] JSON结果已保存: {json_path}")
        
        return report_path


# ============================================================================
# AI反汇编分析器主类
# ============================================================================

class AIDisassemblyAnalyzer:
    """AI反汇编分析器 - 整合所有分析组件的主类"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.pe = None
        self.instructions = []
        self.functions = {}
        self.imports = []
        self.exports = []
        
        # 分析引擎 - 只初始化不需要参数的
        self.disasm_engine = DisassemblyEngine()
        self.ai_team = AITeamManager()
          # 这些分析器会在有数据后才初始化
        self.control_flow = None
        self.data_flow = None
        self.semantic = None
        self.patch_analyzer = None
        
        self.analysis_results = {}
    
    def load(self) -> bool:
        """加载PE文件"""
        try:
            import pefile
            self.pe = pefile.PE(self.file_path)
            
            # 解析导入表
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8') if imp.name and isinstance(imp.name, bytes) else str(imp.ordinal)
                        self.imports.append({
                            'dll': dll_name,
                            'function': func_name,
                            'address': imp.address
                        })
            
            # 解析导出表
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    func_name = exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}"
                    self.exports.append({
                        'name': func_name,
                        'address': exp.address,
                        'ordinal': exp.ordinal
                    })
            
            return True
        except Exception as e:
            print(f"加载文件失败: {e}")
            return False
    
    def disassemble(self):
        """执行反汇编"""
        if not self.pe:
            return
        
        # 获取代码段
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                code_data = section.get_data()
                base_addr = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                self.instructions = self.disasm_engine.disassemble(code_data, base_addr)
                break
    
    def analyze_control_flow(self):
        """分析控制流"""
        if not self.instructions:
            return
        
        # 初始化控制流分析器
        self.control_flow = ControlFlowAnalyzer(self.instructions)
        self.control_flow.build_basic_blocks()
        self.functions = self.control_flow.identify_functions()
    
    def analyze_data_flow(self):
        """分析数据流"""
        if not self.control_flow or not self.control_flow.basic_blocks:
            return
          # 初始化数据流分析器
        self.data_flow = DataFlowAnalyzer(self.control_flow.basic_blocks)
        self.data_flow.analyze_definitions_and_uses()
        self.data_flow.compute_liveness()
    
    def analyze_semantics(self):
        """语义分析"""
        if not self.functions or not self.imports:
            return
        
        # 初始化语义分析器
        self.semantic = SemanticAnalyzer(self.functions, self.imports)
        for func in self.functions.values():
            func.ai_analysis = self.semantic.analyze_function_purpose(func)
    
    def find_patch_points(self):
        """查找可修改点"""
        if not self.instructions:
            return
          # 初始化补丁分析器
        self.patch_analyzer = PatchAnalyzer(self.instructions, self.disasm_engine)
        self.patch_points = self.patch_analyzer.find_patch_points()
    
    def full_analysis(self) -> Dict:
        """执行完整分析"""
        if not self.load():
            return {}
        
        print("[*] 开始反汇编...")
        self.disassemble()
        
        print("[*] 分析控制流...")
        self.analyze_control_flow()
        
        print("[*] 分析数据流...")
        self.analyze_data_flow()
        
        print("[*] 语义分析...")
        self.analyze_semantics()
        
        print("[*] 查找可修改点...")
        self.find_patch_points()
        
        # 准备AI分析数据
        analysis_data = {
            'instructions': self.instructions,
            'functions': self.functions,
            'imports': self.imports,
            'exports': self.exports,
            'patch_points': getattr(self, 'patch_points', [])
        }
        
        print("[*] 启动AI团队分析...")
        self.analysis_results = self.ai_team.run_full_analysis(analysis_data)
        
        return self.analysis_results
    
    def generate_report(self, output_path: str = None) -> str:
        """生成分析报告"""
        # 准备分析器数据以传递给报告生成器
        analyzer_data = {
            'file_path': self.file_path,
            'file_hash': hashlib.sha256(open(self.file_path, 'rb').read()).hexdigest() if os.path.exists(self.file_path) else 'N/A',
            'instructions': self.instructions,
            'basic_blocks': self.control_flow.basic_blocks if self.control_flow else {},
            'functions': self.functions,
            'imports': self.imports,
            'exports': self.exports,
            'patch_points': getattr(self, 'patch_points', [])
        }
        return self.ai_team.generate_report(output_path, analyzer_data)


# ============================================================================
# 交互式分析器
# ============================================================================

class InteractiveAnalyzer: 
    """交互式反汇编分析器"""
    
    def __init__(self):
        self.analyzer = None
        self.current_address = 0
        self.bookmarks = {}
        self.comments = {}
        self.history = []
    
    def run(self):
        """运行交互式模式"""
        print("\n" + "="*70)
        print("  🔬 AI反汇编交互式分析器")
        print("  输入 'help' 查看命令列表")
        print("="*70 + "\n")
        
        while True:
            try:
                prompt = f"0x{self.current_address:08x}> " if self.analyzer else "disasm> "
                cmd = input(prompt).strip()
                
                if not cmd: 
                    continue
                
                self.history.append(cmd)
                parts = cmd.split()
                command = parts[0]. lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in ['exit', 'quit', 'q']:
                    print("再见!")
                    break
                elif command == 'help': 
                    self._show_help()
                elif command == 'load':
                    self._load_file(args)
                elif command == 'analyze':
                    self._run_analysis()
                elif command == 'disasm':
                    self._show_disasm(args)
                elif command == 'func':
                    self._show_function(args)
                elif command == 'funcs':
                    self._list_functions()
                elif command == 'imports':
                    self._show_imports(args)
                elif command == 'xref':
                    self._show_xrefs(args)
                elif command == 'patch':
                    self._show_patches(args)
                elif command == 'goto':
                    self._goto_address(args)
                elif command == 'search':
                    self._search(args)
                elif command == 'ai':
                    self._ai_analysis()
                elif command == 'comment':
                    self._add_comment(args)
                elif command == 'bookmark':
                    self._manage_bookmark(args)
                elif command == 'export':
                    self._export_results(args)
                elif command == 'pseudo':
                    self._show_pseudocode(args)
                elif command == 'graph':
                    self._show_cfg(args)
                elif command == 'strings':
                    self._show_strings()
                elif command == 'info':
                    self._show_info()
                else:
                    print(f"未知命令: {command}.  输入 'help' 查看帮助.")
                    
            except KeyboardInterrupt: 
                print("\n使用 'exit' 退出")
            except Exception as e: 
                print(f"错误: {e}")
    
    def _show_help(self):
        """显示帮助"""
        help_text = """
=== 文件操作 ===
  load <文件>          加载PE文件
  analyze             执行完整分析
  info                显示文件信息
  export [文件]        导出分析结果

=== 反汇编查看 ===
  disasm [地址] [数量]  显示反汇编 (默认当前地址, 20条)
  goto <地址>          跳转到地址
  func [地址/名称]     显示函数详情
  funcs               列出所有函数
  pseudo [地址]        显示伪代码

=== 分析功能 ===
  imports [过滤]       显示导入表
  xref <地址>          显示交叉引用
  patch [地址]         显示可修改点
  search <模式>        搜索指令/字符串
  strings             显示字符串
  graph [地址]         显示控制流图

=== AI分析 ===
  ai                  运行AI团队分析
  
=== 注释和书签 ===
  comment <地址> <内容>  添加注释
  bookmark [add/del/list] <地址> <名称>  管理书签

=== 其他 ===
  help                显示帮助
  exit/quit           退出
"""
        print(help_text)
    
    def _load_file(self, args:  List[str]):
        """加载文件"""
        if not args:
            print("用法: load <文件路径>")
            return
        
        file_path = ' '.join(args)
        
        if not os.path. exists(file_path):
            print(f"文件不存在: {file_path}")
            return
        
        self.analyzer = AIDisassemblyAnalyzer(file_path)
        if self.analyzer.load():
            print("文件加载成功，使用 'analyze' 执行分析")
            
            # 设置初始地址
            if self.analyzer.pe: 
                self.current_address = self.analyzer.pe. OPTIONAL_HEADER.ImageBase + \
                                      self.analyzer.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    
    def _run_analysis(self):
        """执行分析"""
        if not self.analyzer:
            print("请先加载文件:  load <文件>")
            return
        
        self.analyzer.disassemble()
        self.analyzer.analyze_control_flow()
        self.analyzer.analyze_data_flow()
        self.analyzer.analyze_semantics()
        self.analyzer.find_patch_points()
        
        print("\n分析完成!  使用以下命令查看结果:")
        print("  funcs    - 列出函数")
        print("  disasm   - 查看反汇编")
        print("  patch    - 查看可修改点")
        print("  ai       - AI团队分析")
    
    def _show_disasm(self, args: List[str]):
        """显示反汇编"""
        if not self.analyzer or not self.analyzer. instructions:
            print("请先执行分析")
            return
        
        # 解析参数
        address = self.current_address
        count = 20
        
        if args:
            try: 
                address = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
            except ValueError:
                print(f"无效地址: {args[0]}")
                return
            
            if len(args) > 1:
                try: 
                    count = int(args[1])
                except ValueError:
                    pass
        
        # 查找并显示指令
        found = False
        displayed = 0
        
        for instr in self.analyzer.instructions:
            if instr.address >= address:
                if not found:
                    found = True
                
                # 显示书签和注释
                prefix = ""
                if hex(instr.address) in self.bookmarks:
                    prefix = f"📌 [{self.bookmarks[hex(instr. address)]}] "
                
                comment = ""
                if hex(instr.address) in self.comments:
                    comment = f"  ; {self.comments[hex(instr. address)]}"
                
                # 高亮特殊指令
                highlight = ""
                if instr.is_call: 
                    highlight = "📞"
                elif instr.is_ret:
                    highlight = "🔙"
                elif instr.is_conditional: 
                    highlight = "🔀"
                elif instr.is_jump:
                    highlight = "➡️"
                
                print(f"{prefix}0x{instr. address:08x}:  {instr.bytes.hex(): <20} {instr.mnemonic: <8} {instr.op_str: <30} {highlight}{comment}")
                
                displayed += 1
                if displayed >= count: 
                    break
        
        if not found:
            print(f"未找到地址 0x{address:x} 处的指令")
        else:
            # 更新当前地址
            self.current_address = address
    
    def _show_function(self, args: List[str]):
        """显示函数详情"""
        if not self.analyzer or not self.analyzer. functions:
            print("请先执行分析")
            return
        
        if not args: 
            # 显示当前地址所在函数
            func = self._find_function_at(self.current_address)
            if not func:
                print("当前地址不在任何函数内")
                return
        else:
            # 按名称或地址查找
            query = args[0]
            func = None
            
            # 尝试按地址查找
            try:
                addr = int(query, 16) if query.startswith('0x') else int(query)
                func = self. analyzer.functions.get(addr)
            except ValueError:
                pass
            
            # 尝试按名称查找
            if not func:
                for f in self.analyzer. functions.values():
                    if query. lower() in f.name.lower():
                        func = f
                        break
            
            if not func:
                print(f"未找到函数:  {query}")
                return
        
        # 显示函数信息
        print(f"\n{'='*60}")
        print(f"函数:  {func.name}")
        print(f"{'='*60}")
        print(f"地址:      0x{func. address:08x}")
        print(f"大小:     {func.size} bytes")
        print(f"基本块:   {len(func.basic_blocks)} 个")
        print(f"调用:      {len(func.calls)} 个")
        
        if func.ai_analysis:
            print(f"\nAI分析:")
            print(f"  描述: {func. ai_analysis.get('description', 'N/A')}")
            print(f"  可疑:  {'是' if func.ai_analysis.get('is_suspicious') else '否'}")
            if func.ai_analysis.get('api_categories'):
                print(f"  API类别: {', '. join(func.ai_analysis['api_categories'])}")
        
        print(f"\n调用的函数:")
        for call_addr in func.calls[: 10]: 
            target_name = self._resolve_call_target(call_addr)
            print(f"  0x{call_addr:08x}:  {target_name}")
        
        if len(func.calls) > 10:
            print(f"  ... 还有 {len(func.calls) - 10} 个")
    
    def _find_function_at(self, address: int) -> Optional[Function]:
        """查找包含指定地址的函数"""
        for func in self.analyzer. functions.values():
            if func.address <= address < func.end_address:
                return func
        return None
    
    def _resolve_call_target(self, address: int) -> str:
        """解析调用目标名称"""
        # 检查是否是导入函数
        for imp in self.analyzer. imports:
            if imp.get('address') == hex(address):
                return f"{imp['dll']}! {imp['function']}"
        
        # 检查是否是已知函数
        if address in self.analyzer.functions:
            return self.analyzer. functions[address].name
        
        return "unknown"
    
    def _list_functions(self):
        """列出所有函数"""
        if not self.analyzer or not self.analyzer. functions:
            print("请先执行分析")
            return
        
        print(f"\n函数列表 ({len(self.analyzer.functions)} 个):\n")
        print(f"{'地址':<14} {'名称':<30} {'大小':<10} {'块数':<8} {'调用数'}")
        print("-" * 75)
        
        for addr, func in sorted(self.analyzer. functions.items()):
            suspicious = "⚠️" if func.ai_analysis.get('is_suspicious') else ""
            print(f"0x{addr:08x}   {func.name:<30} {func. size: <10} {len(func.basic_blocks):<8} {len(func.calls)} {suspicious}")
    
    def _show_imports(self, args: List[str]):
        """显示导入表"""
        if not self.analyzer:
            print("请先加载文件")
            return
        
        imports = self.analyzer. imports
        filter_text = ' '.join(args).lower() if args else None
        
        if filter_text: 
            imports = [i for i in imports
                      if filter_text in i. get('dll', '').lower()
                      or filter_text in i. get('function', '').lower()]
        
        print(f"\n导入函数 ({len(imports)} 个):\n")
        
        # 按DLL分组
        by_dll = defaultdict(list)
        for imp in imports:
            by_dll[imp['dll']].append(imp)
        
        for dll, funcs in sorted(by_dll.items()):
            print(f"[{dll}] ({len(funcs)} 个)")
            for f in funcs[: 15]: 
                print(f"  {f['address']}:  {f['function']}")
            if len(funcs) > 15:
                print(f"  ... 还有 {len(funcs) - 15} 个")
            print()
    
    def _show_xrefs(self, args: List[str]):
        """显示交叉引用"""
        if not self.analyzer:
            print("请先执行分析")
            return
        
        if not args:
            print("用法: xref <地址>")
            return
        
        try:
            address = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
        except ValueError:
            print(f"无效地址: {args[0]}")
            return
        
        print(f"\n交叉引用 0x{address: 08x}:\n")
        
        # 查找引用此地址的指令
        refs_to = []
        refs_from = []
        
        for instr in self.analyzer.instructions:
            if instr.branch_target == address:
                refs_to.append(instr)
            if instr.address == address:
                if instr.branch_target:
                    refs_from. append(instr)
        
        print("引用到此地址:")
        for ref in refs_to[: 20]: 
            print(f"  0x{ref.address:08x}: {ref.mnemonic} {ref.op_str}")
        
        if not refs_to: 
            print("  (无)")
        
        print("\n从此地址引用:")
        for ref in refs_from[:20]:
            print(f"  -> 0x{ref.branch_target:08x}")
        
        if not refs_from: 
            print("  (无)")
    
    def _show_patches(self, args: List[str]):
        """显示可修改点"""
        if not self.analyzer or not self.analyzer. patch_points:
            print("请先执行分析")
            return
        
        patches = self.analyzer. patch_points
        
        # 按类型过滤
        if args:
            filter_type = args[0]. lower()
            patches = [p for p in patches if filter_type in p. patch_type. lower()]
        
        print(f"\n可修改点 ({len(patches)} 个):\n")
        
        # 按风险级别排序
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        patches = sorted(patches, key=lambda x: risk_order.get(x.risk_level, 4))
        
        for i, patch in enumerate(patches[:30], 1):
            risk_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW':  '🟢'}.get(patch. risk_level, '⚪')
            
            print(f"{i: 3}. {risk_icon} 0x{patch.address:08x} [{patch.patch_type}]")
            print(f"     原始:  {patch.original_instruction}")
            print(f"     描述: {patch. description}")
            
            if patch.suggested_patches:
                print(f"     补丁选项:")
                for j, sugg in enumerate(patch. suggested_patches[: 3], 1):
                    bytes_hex = sugg['bytes'].hex() if sugg.get('bytes') else 'N/A'
                    print(f"       {j}) {sugg['name']}:  {bytes_hex}")
            print()
        
        if len(self.analyzer.patch_points) > 30:
            print(f"... 还有 {len(self.analyzer.patch_points) - 30} 个")
    
    def _goto_address(self, args: List[str]):
        """跳转到地址"""
        if not args:
            print("用法: goto <地址>")
            return
        
        try:
            address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
            self.current_address = address
            print(f"跳转到 0x{address:08x}")
            self._show_disasm([])
        except ValueError: 
            print(f"无效地址: {args[0]}")
    
    def _search(self, args: List[str]):
        """搜索"""
        if not self.analyzer or not self.analyzer. instructions:
            print("请先执行分析")
            return
        
        if not args:
            print("用法:  search <模式>")
            print("示例: search call")
            print("      search push ebp")
            return
        
        pattern = ' '.join(args).lower()
        matches = []
        
        for instr in self.analyzer.instructions:
            full_instr = f"{instr.mnemonic} {instr.op_str}". lower()
            if pattern in full_instr:
                matches.append(instr)
        
        print(f"\n搜索 '{pattern}' 找到 {len(matches)} 个结果:\n")
        
        for instr in matches[: 30]:
            print(f"  0x{instr.address:08x}: {instr.mnemonic} {instr.op_str}")
        
        if len(matches) > 30:
            print(f"\n... 还有 {len(matches) - 30} 个结果")
    
    def _ai_analysis(self):
        """运行AI分析"""
        if not self.analyzer:
            print("请先加载并分析文件")
            return
        
        if not self.analyzer. instructions:
            print("请先执行 'analyze' 命令")
            return
        
        results = self.analyzer. run_ai_analysis()
        
        # 显示共识摘要
        consensus = results.get('consensus', {})
        print(f"\n{'='*60}")
        print("🤖 AI团队分析结果")
        print(f"{'='*60}")
        print(f"\n整体评估:  {consensus.get('overall_assessment', 'N/A')}")
        print(f"风险级别: {consensus.get('risk_level', 'UNKNOWN')}")
        
        print(f"\n关键发现:")
        for finding in consensus.get('key_findings', [])[:5]:
            print(f"  - [{finding['priority']}] {finding['finding']}")
        
        print(f"\n优先修改目标:")
        for target in consensus.get('priority_targets', [])[:5]:
            print(f"  - {target['address']}:  {target['action']}")
        
        print(f"\n使用 'export' 命令保存完整报告")
    
    def _add_comment(self, args: List[str]):
        """添加注释"""
        if len(args) < 2:
            print("用法: comment <地址> <内容>")
            return
        
        try:
            address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
            comment = ' '.join(args[1:])
            self.comments[hex(address)] = comment
            print(f"注释已添加: 0x{address:08x} ; {comment}")
        except ValueError:
            print(f"无效地址: {args[0]}")
    
    def _manage_bookmark(self, args: List[str]):
        """管理书签"""
        if not args:
            # 列出书签
            if self.bookmarks:
                print("\n书签列表:")
                for addr, name in self.bookmarks.items():
                    print(f"  {addr}:  {name}")
            else:
                print("无书签")
            return
        
        action = args[0]. lower()
        
        if action == 'add' and len(args) >= 3:
            try:
                address = int(args[1], 16) if args[1]. startswith('0x') else int(args[1])
                name = ' '.join(args[2:])
                self.bookmarks[hex(address)] = name
                print(f"书签已添加: {name} @ 0x{address:08x}")
            except ValueError: 
                print(f"无效地址:  {args[1]}")
        elif action == 'del' and len(args) >= 2:
            addr = args[1] if args[1]. startswith('0x') else f"0x{int(args[1]):x}"
            if addr in self.bookmarks:
                del self.bookmarks[addr]
                print(f"书签已删除: {addr}")
            else:
                print(f"书签不存在: {addr}")
        elif action == 'list': 
            self._manage_bookmark([])
        else:
            print("用法: bookmark [add <地址> <名称>|del <地址>|list]")
    
    def _export_results(self, args: List[str]):
        """导出结果"""
        if not self. analyzer:
            print("请先加载并分析文件")
            return
        
        output_path = args[0] if args else "output"
        report_path = self.analyzer.generate_report(output_path)
        print(f"报告已导出到: {report_path}")
    
    def _show_pseudocode(self, args: List[str]):
        """显示伪代码"""
        if not self.analyzer or not self.analyzer.functions:
            print("请先执行分析")
            return
        
        # 获取函数
        if args:
            try:
                address = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
                func = self.analyzer. functions.get(address)
            except ValueError:
                func = None
        else:
            func = self._find_function_at(self.current_address)
        
        if not func:
            print("未找到函数")
            return
        
        print(f"\n// 函数:  {func.name}")
        print(f"// 地址: 0x{func.address:08x}")
        print(f"// 大小: {func.size} bytes")
        print()
        
        # 生成简化伪代码
        pseudocode = self._generate_pseudocode(func)
        print(pseudocode)
    
    def _generate_pseudocode(self, func: Function) -> str:
        """生成伪代码"""
        lines = []
        lines.append(f"int {func.name}() {{")
        
        # 分析函数结构
        indent = "    "
        
        for bb in func.basic_blocks:
            lines.append(f"\n{indent}// 基本块 0x{bb.start_address:08x}")
            
            for instr in bb. instructions:
                pseudo = self._instruction_to_pseudo(instr)
                if pseudo: 
                    lines.append(f"{indent}{pseudo}")
            
            # 处理跳转
            if bb.instructions:
                last = bb.instructions[-1]
                if last.is_conditional:
                    lines.append(f"{indent}if (condition) goto 0x{last.branch_target:x};")
                elif last.is_jump and not last.is_ret:
                    lines.append(f"{indent}goto 0x{last.branch_target:x};")
        
        lines.append("}")
        return '\n'.join(lines)
    
    def _instruction_to_pseudo(self, instr: Instruction) -> str:
        """将指令转换为伪代码"""
        mnemonic = instr.mnemonic. lower()
        op = instr.op_str
        
        if mnemonic == 'mov':
            parts = op.split(',')
            if len(parts) == 2:
                return f"{parts[0]. strip()} = {parts[1].strip()};"
        elif mnemonic == 'add': 
            parts = op.split(',')
            if len(parts) == 2:
                return f"{parts[0].strip()} += {parts[1]. strip()};"
        elif mnemonic == 'sub': 
            parts = op. split(',')
            if len(parts) == 2:
                return f"{parts[0].strip()} -= {parts[1].strip()};"
        elif mnemonic == 'xor':
            parts = op.split(',')
            if len(parts) == 2:
                if parts[0].strip() == parts[1].strip():
                    return f"{parts[0].strip()} = 0;  // xor self"
                return f"{parts[0]. strip()} ^= {parts[1].strip()};"
        elif mnemonic == 'push':
            return f"push({op});"
        elif mnemonic == 'pop':
            return f"{op} = pop();"
        elif mnemonic == 'call':
            return f"call {op};"
        elif mnemonic == 'ret':
            return "return;"
        elif mnemonic == 'cmp':
            return f"// compare {op}"
        elif mnemonic == 'test':
            return f"// test {op}"
        elif mnemonic == 'nop':
            return None
        elif mnemonic == 'lea':
            parts = op.split(',')
            if len(parts) == 2:
                return f"{parts[0].strip()} = &{parts[1]. strip()};"
        elif mnemonic in ['inc']: 
            return f"{op}++;"
        elif mnemonic in ['dec']:
            return f"{op}--;"
        
        return f"// {instr.mnemonic} {instr. op_str}"
    
    def _show_cfg(self, args:  List[str]):
        """显示控制流图"""
        if not self. analyzer or not self. analyzer.functions:
            print("请先执行分析")
            return
        
        # 获取函数
        if args: 
            try: 
                address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
                func = self.analyzer.functions. get(address)
            except ValueError: 
                func = None
        else:
            func = self._find_function_at(self.current_address)
        
        if not func: 
            print("未找到函数")
            return
        
        print(f"\n控制流图:  {func.name}")
        print(f"{'='*50}\n")
        
        for bb in func.basic_blocks:
            print(f"┌─ 基本块 0x{bb.start_address:08x} ─┐")
            for instr in bb. instructions[: 5]:
                print(f"│ {instr.mnemonic: <6} {instr. op_str:<20} │")
            if len(bb.instructions) > 5:
                print(f"│ ... ({len(bb.instructions) - 5} more)          │")
            print(f"└─────────────────────────────┘")
            
            if bb.successors:
                for succ in bb. successors:
                    print(f"         │")
                    print(f"         ▼ 0x{succ: 08x}")
            print()
    
    def _show_strings(self):
        """显示字符串"""
        if not self. analyzer or not self. analyzer.file_data:
            print("请先加载文件")
            return
        
        # 提取ASCII字符串
        strings = []
        current = b""
        start_offset = 0
        
        for i, byte in enumerate(self.analyzer.file_data):
            if 0x20 <= byte <= 0x7E: 
                if not current:
                    start_offset = i
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    try:
                        strings.append((start_offset, current. decode('ascii')))
                    except: 
                        pass
                current = b""
        
        print(f"\n字符串 ({len(strings)} 个):\n")
        
        # 过滤有意义的字符串
        interesting = []
        keywords = ['http', 'www', 'password', 'error', 'file', 'open', 'create', 
                   'registry', 'key', 'value', 'dll', 'exe', 'cmd']
        
        for offset, s in strings:
            if any(kw in s.lower() for kw in keywords):
                interesting.append((offset, s, True))
            elif len(s) > 10:
                interesting.append((offset, s, False))
        
        for offset, s, is_interesting in interesting[: 50]:
            marker = "⭐" if is_interesting else "  "
            display = s[: 60] + "..." if len(s) > 60 else s
            print(f"{marker} 0x{offset: 08x}: {display}")
        
        if len(interesting) > 50:
            print(f"\n... 还有 {len(interesting) - 50} 个")
    
    def _show_info(self):
        """显示文件信息"""
        if not self. analyzer:
            print("请先加载文件")
            return
        
        print(f"\n文件信息:")
        print(f"{'='*50}")
        print(f"路径: {self. analyzer.file_path}")
        print(f"大小:  {len(self.analyzer. file_data):,} bytes")
        
        if self.analyzer.pe: 
            pe = self.analyzer.pe
            print(f"\nPE信息:")
            print(f"  架构: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
            print(f"  入口点: 0x{pe. OPTIONAL_HEADER. AddressOfEntryPoint:08x}")
            print(f"  镜像基址: 0x{pe.OPTIONAL_HEADER.ImageBase:08x}")
            print(f"  节数量: {pe.FILE_HEADER.NumberOfSections}")
            
            print(f"\n节表:")
            for section in pe.sections:
                name = section.Name. decode('utf-8').strip('\x00')
                print(f"  {name: <10} VA: 0x{section.VirtualAddress:08x}  Size: {section. Misc_VirtualSize:>8}")
        
        if self.analyzer.instructions:
            print(f"\n分析状态:")
            print(f"  指令:  {len(self. analyzer.instructions)}")
            print(f"  基本块: {len(self.analyzer. basic_blocks)}")
            print(f"  函数: {len(self.analyzer.functions)}")
            print(f"  导入: {len(self.analyzer.imports)}")
            print(f"  可修改点: {len(self.analyzer.patch_points)}")


# ============================================================================
# 补丁生成器
# ============================================================================

class PatchGenerator:
    """补丁文件生成器"""
    
    def __init__(self, analyzer: AIDisassemblyAnalyzer):
        self.analyzer = analyzer
    
    def generate_ips_patch(self, patches: List[Tuple[int, bytes]], output_path: str) -> bool:
        """生成IPS格式补丁"""
        try:
            with open(output_path, 'wb') as f:
                # IPS头
                f.write(b'PATCH')
                
                for offset, data in patches:
                    if offset > 0xFFFFFF: 
                        print(f"警告: 偏移 0x{offset:x} 超出IPS范围")
                        continue
                    
                    # 3字节偏移
                    f.write(offset.to_bytes(3, 'big'))
                    # 2字节长度
                    f.write(len(data).to_bytes(2, 'big'))
                    # 数据
                    f.write(data)
                
                # IPS尾
                f.write(b'EOF')
            
            print(f"IPS补丁已生成: {output_path}")
            return True
            
        except Exception as e:
            print(f"生成IPS补丁失败: {e}")
            return False
    
    def generate_python_patcher(self, patches:  List[Dict], output_path: str) -> bool:
        """生成Python补丁脚本"""
        script = '''#!/usr/bin/env python3
"""
自动生成的补丁脚本
目标文件: {target}
生成时间: {timestamp}
"""

import os
import sys
import shutil

# 补丁定义
PATCHES = [
'''.format(
            target=os.path.basename(self.analyzer.file_path),
            timestamp=datetime.now().isoformat()
        )
        
        for patch in patches: 
            script += f'''    {{
        'name': '{patch. get("name", "unnamed")}',
        'offset': 0x{patch. get("offset", 0):x},
        'original':  bytes.fromhex('{patch.get("original", b"").hex()}'),
        'patched': bytes.fromhex('{patch.get("patched", b"").hex()}'),
        'description': '{patch.get("description", "")}'
    }},
'''
        
        script += ''']

def apply_patches(file_path, create_backup=True):
    """应用补丁"""
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return False
    
    # 创建备份
    if create_backup: 
        backup_path = file_path + '.bak'
        if not os.path.exists(backup_path):
            shutil. copy2(file_path, backup_path)
            print(f"已创建备份:  {backup_path}")
    
    # 读取文件
    with open(file_path, 'rb') as f:
        data = bytearray(f. read())
    
    # 应用补丁
    applied = 0
    for patch in PATCHES: 
        offset = patch['offset']
        original = patch['original']
        patched = patch['patched']
        
        # 验证原始字节
        current = bytes(data[offset: offset + len(original)])
        if current == original:
            data[offset:offset + len(patched)] = patched
            print(f"[✓] 已应用:  {patch['name']}")
            applied += 1
        elif current == patched: 
            print(f"[=] 已存在: {patch['name']}")
        else:
            print(f"[✗] 不匹配: {patch['name']}")
            print(f"    预期: {original. hex()}")
            print(f"    实际: {current.hex()}")
    
    # 写入文件
    if applied > 0:
        with open(file_path, 'wb') as f:
            f.write(data)
        print(f"\\n成功应用 {applied} 个补丁")
    else:
        print("\\n没有补丁被应用")
    
    return applied > 0

def restore_backup(file_path):
    """恢复备份"""
    backup_path = file_path + '.bak'
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, file_path)
        print(f"已恢复:  {file_path}")
        return True
    else:
        print(f"备份不存在: {backup_path}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <目标文件> [--restore]")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2 and sys.argv[2] == '--restore':
        restore_backup(target)
    else:
        apply_patches(target)
'''
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"Python补丁脚本已生成:  {output_path}")
            return True
        except Exception as e: 
            print(f"生成补丁脚本失败: {e}")
            return False
    
    def generate_x64dbg_script(self, patches:  List[Dict], output_path: str) -> bool:
        """生成x64dbg脚本"""
        script = f'''// x64dbg补丁脚本
// 目标:  {os.path. basename(self.analyzer.file_path)}
// 生成时间: {datetime.now().isoformat()}

// 使用方法:  在x64dbg中执行 scriptload "{output_path}"

log "开始应用补丁..."

'''
        
        for i, patch in enumerate(patches, 1):
            offset = patch. get('offset', 0)
            patched = patch.get('patched', b'')
            name = patch.get('name', f'patch_{i}')
            
            script += f'// 补丁 {i}:  {name}\n'
            script += f'// {patch.get("description", "")}\n'
            
            # 写入每个字节
            for j, byte in enumerate(patched):
                script += f'writebyte {offset + j: x}, {byte:02x}\n'
            
            script += '\n'
        
        script += '''log "补丁应用完成"
ret
'''
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"x64dbg脚本已生成: {output_path}")
            return True
        except Exception as e:
            print(f"生成x64dbg脚本失败:  {e}")
            return False


# ============================================================================
# 命令行接口
# ============================================================================

def print_banner():
    """打印横幅"""
    banner = f"""
{'='*70}
    🔬 AI团队反汇编分析工具 v1.0
    
    核心功能: 
    ✓ 智能反汇编 (x86/x64)      ✓ 控制流分析
    ✓ 数据流分析                ✓ 语义分析
    ✓ 可修改点识别              ✓ 补丁生成
    
    AI团队: 
    ✓ 逻辑分析师                ✓ 安全分析师
    ✓ 补丁专家                  ✓ 逆向工程师
    ✓ 行为分析师
    
    依赖状态:
    - pefile:    {'✓ 已安装' if HAS_PEFILE else '✗ 未安装 (pip install pefile)'}
    - capstone: {'✓ 已安装' if HAS_CAPSTONE else '✗ 未安装 (pip install capstone)'}
    - keystone: {'✓ 已安装' if HAS_KEYSTONE else '✗ 未安装 (pip install keystone-engine)'}
{'='*70}
"""
    print(banner)


def print_usage():
    """打印使用说明"""
    usage = f"""
用法:  python {sys.argv[0]} <命令> [选项]

命令:
    analyze <文件>      分析PE文件
    interactive         进入交互式模式
    patch <文件>        生成补丁脚本
    help               显示帮助

选项:
    --output <目录>     指定输出目录
    --no-ai            跳过AI分析
    --format <格式>     补丁格式 (python/ips/x64dbg)

示例:
    python {sys.argv[0]} analyze malware.exe
    python {sys.argv[0]} interactive
    python {sys. argv[0]} patch target.exe --format python
"""
    print(usage)


def main():
    """主函数"""
    print_banner()
    
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    
    command = sys.argv[1]. lower()
    
    if command == 'help':
        print_usage()
        sys.exit(0)
    
    elif command == 'interactive' or command == '-i':
        interactive = InteractiveAnalyzer()
        interactive.run()
    
    elif command == 'analyze':
        if len(sys.argv) < 3:
            print("错误: 请指定要分析的文件")
            print_usage()
            sys.exit(1)
        
        file_path = sys. argv[2]
        
        if not os.path. exists(file_path):
            print(f"文件不存在: {file_path}")
            sys.exit(1)
        
        # 解析选项
        output_dir = "output"
        run_ai = True
        
        for i, arg in enumerate(sys.argv[3:], 3):
            if arg == '--output' and i + 1 < len(sys.argv):
                output_dir = sys.argv[i + 1]
            elif arg == '--no-ai':
                run_ai = False
        
        # 执行分析
        analyzer = AIDisassemblyAnalyzer(file_path)
        results = analyzer.full_analysis()
        
        if results:
            # 生成报告
            report_path = analyzer.generate_report(output_dir)
            
            # 显示摘要
            print(f"\n{'='*60}")
            print("分析完成")
            print(f"{'='*60}")
            
            consensus = analyzer.ai_team.analysis_results. get('consensus', {})
            print(f"\n风险级别: {consensus. get('risk_level', 'UNKNOWN')}")
            print(f"整体评估: {consensus.get('overall_assessment', 'N/A')}")
            
            print(f"\n优先修改目标:")
            for target in consensus.get('priority_targets', [])[:3]:
                print(f"  - {target['address']}: {target['action']}")
            
            print(f"\n报告已保存:  {report_path}")
    
    elif command == 'patch': 
        if len(sys.argv) < 3:
            print("错误: 请指定要分析的文件")
            sys.exit(1)
        
        file_path = sys. argv[2]
        
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            sys.exit(1)
        
        # 解析格式
        patch_format = 'python'
        for i, arg in enumerate(sys.argv[3:], 3):
            if arg == '--format' and i + 1 < len(sys. argv):
                patch_format = sys. argv[i + 1]. lower()
        
        # 分析
        analyzer = AIDisassemblyAnalyzer(file_path)
        analyzer.load()
        analyzer.disassemble()
        analyzer.analyze_control_flow()
        analyzer.find_patch_points()
        
        # 生成补丁
        generator = PatchGenerator(analyzer)
        
        patches = []
        for pp in analyzer.patch_points[: 10]:  # 只取前10个
            if pp.suggested_patches:
                sugg = pp.suggested_patches[0]
                if sugg.get('bytes'):
                    patches. append({
                        'name': f"patch_{pp.address:x}",
                        'offset':  pp.address,
                        'original':  pp.original_bytes,
                        'patched': sugg['bytes'],
                        'description': sugg['description']
                    })
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if patch_format == 'python':
            generator.generate_python_patcher(patches, f"output/patcher_{timestamp}.py")
        elif patch_format == 'ips': 
            ips_patches = [(p['offset'], p['patched']) for p in patches]
            generator.generate_ips_patch(ips_patches, f"output/patch_{timestamp}.ips")
        elif patch_format == 'x64dbg':
            generator. generate_x64dbg_script(patches, f"output/patch_{timestamp}.x64dbg. txt")
        else:
            print(f"不支持的格式: {patch_format}")
    
    else: 
        print(f"未知命令: {command}")
        print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()