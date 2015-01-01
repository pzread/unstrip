import os
import re
import hashlib
import struct
import msgpack
import subprocess
from collections import *
from elftools.elf.elffile import *
from capstone import *
from capstone.x86_const import *

md = Cs(CS_ARCH_X86,CS_MODE_64)
md.detail = True

class Section(object):
    def __init__(self,obj,shndx,elf_sec):
        self.obj = obj
        self.idx = shndx
        self.base = elf_sec.header['sh_addr']
        self.size = elf_sec.header['sh_size']
        self.type = elf_sec.header['sh_type']
        self.flags = elf_sec.header['sh_flags']
        self.reloc = {}
        self.data = bytearray(elf_sec.data())
        self.ins_cache = {}

class Symbol(object):
    def __init__(self,obj,stndx,elf_sym):
        self.obj = obj
        self.idx = stndx
        self.name = elf_sym.name
        self.value = elf_sym.entry['st_value']
        self.size = elf_sym.entry['st_size']
        self.shndx = elf_sym.entry['st_shndx']
        self.type = elf_sym.entry['st_info']['type']
        self.link = None

class Reloc(object):
    def __init__(self,obj,shndx,elf_reloc):
        self.obj = obj
        self.reloc_shndx = shndx
        self.type = elf_reloc.entry['r_info_type']
        self.offset = elf_reloc.entry['r_offset']
        obj.section[shndx].reloc[self.offset] = self
        self.size = 0
        self.field = None

        s = elf_reloc.entry['r_info_sym']
        a = elf_reloc.entry['r_addend']
        p = self.offset

        if self.type == 1:
            self.size = 8
            self.field = (s,a)
        elif self.type == 2:
            self.size = 4
            self.field = (s,a - p)
        elif self.type == 10:
            self.size = 4
            self.field = (s,a)
        elif self.type == 11:
            self.size = 4
            self.field = (s,a)

class ELF(object):
    def __init__(self,path,name):
        elf = ELFFile(open(path,'rb'))
        self.name = name
        self.path = path
        self.elf = elf
        self.section = []

        for idx,elf_sec in enumerate(elf.iter_sections()):
            self.section.append(Section(self,idx,elf_sec))

class OBJ(ELF):
    def __init__(self,path,name):
        super(OBJ,self).__init__(path,name)
        self.sym_list = []
        self.sym_export = {}
        self.sym_import = {}
        self.reloc = []

        for elf_sec in self.elf.iter_sections():
            if elf_sec.header['sh_type'] == 'SHT_SYMTAB':
                for stndx,elf_sym in enumerate(elf_sec.iter_symbols()):
                    sym = Symbol(self,stndx,elf_sym)
                    self.sym_list.append(sym)
                    if (elf_sym.entry['st_info']['bind'] not in
                            ['STB_GLOBAL','STB_WEAK']):
                        continue

                    if sym.type == 'STT_FUNC':
                        sym.link = sym
                        self.sym_export[elf_sym.name] = sym

                    elif sym.type == 'STT_NOTYPE':
                        self.sym_import[elf_sym.name] = sym

                    elif sym.type == 'STT_LOOS':    #STT_GNU_IFUNC
                        pass

            elif elf_sec.header['sh_type'] == 'SHT_RELA':
                for elf_reloc in elf_sec.iter_relocations():
                    if not elf_reloc.is_RELA():
                        continue

                    self.reloc.append(
                            Reloc(self,elf_sec.header['sh_info'],elf_reloc))

class EXE(ELF):
    def __init__(self,path,name):
        super(EXE,self).__init__(path,name)
        self.code_sec = []
        self.sec_cache = None

        for sec in self.section:
            if sec.type == 'SHT_PROGBITS' and (sec.flags & 0x4) != 0:
                self.code_sec.append(sec)

    def GetSection(self,pc):
        if (self.sec_cache != None and
                pc >= self.sec_cache.base and
                pc < self.sec_cache.base + self.sec_cache.size):
            return self.sec_cache,pc - self.sec_cache.base

        for sec in self.code_sec:
            if pc >= sec.base and pc < sec.base + sec.size:
                self.sec_cache = sec
                return sec,pc - sec.base

        return None,None

    def GetTarget(self,op):
        if op.type == X86_OP_IMM:
            return self.GetSection(op.value.imm)
        return None,None

    def ScanBlock(self,loc):
        call_loc = set()
        worklist = deque()
        vis = set()
        worklist.append(loc)
        while len(worklist) > 0:
            loc = worklist.pop()
            if loc in vis:
                continue
            sec,off = loc
            if sec == None:
                continue
            vis.add(loc)
            ins,relflag = Disasm(sec,off,sec.base)
            if ins == None:
                continue

            #print('0x%016lx %s %s'%(ins.address,ins.mnemonic,ins.op_str))
            if ins.id == X86_INS_JMP:
                worklist.append(self.GetTarget(ins.operands[0]))

            elif X86_GRP_RET in ins.groups:
                pass

            elif X86_GRP_JUMP in ins.groups:
                worklist.append(self.GetSection(ins.address + ins.size))
                worklist.append(self.GetTarget(ins.operands[0]))

            elif ins.id == X86_INS_CALL:
                worklist.append(self.GetSection(ins.address + ins.size))
                target_loc = self.GetTarget(ins.operands[0])
                if target_loc != (None,None):
                    call_loc.add((loc,target_loc))
                    worklist.append(target_loc)

            else:
                worklist.append(self.GetSection(ins.address + ins.size))

        return call_loc

    def FuncFin(self,loc,vis):
        fin = []
        while loc not in vis:
            sec,off = loc
            if sec == None:
                break
            vis.add(loc)
            ins,relflag = Disasm(sec,off,sec.base)
            if ins == None:
                break
            fin.append(GetFin(ins,relflag))

            if ins.id == X86_INS_JMP:
                loc = self.GetTarget(ins.operands[0])
            elif ins.id == X86_INS_CALL:
                loc = self.GetSection(ins.address + ins.size)
            elif X86_GRP_RET in ins.groups:
                break
            else:
                loc = self.GetSection(ins.address + ins.size)

        return fin

def Resolve(objdic):
    export = {}
    for obj in objdic.values():
        export.update(obj.sym_export)

    for obj in objdic.values():
        for sym in obj.sym_import.values():
            if sym.name in export:
                sym.link = export[sym.name]

    for obj in objdic.values():
        for reloc in obj.reloc:
            if reloc.field == None:
                continue

            patch = struct.pack('q',reloc.field[1])[:reloc.size]
            sec = obj.section[reloc.reloc_shndx]
            for i in range(reloc.size):
                sec.data[reloc.offset + i] = patch[i]

def GetOpVal(op):
    if op.type == X86_OP_IMM:
        return op.imm
    return None

def GetTarget(ori_sec,op_off,op):
    toff = GetOpVal(op)
    if toff == None:
        return None

    if op_off not in ori_sec.reloc:
        return ori_sec,toff

    field = ori_sec.reloc[op_off].field
    if field == None:
        return None

    stndx = field[0]
    if stndx == None:
        return ori_sec,toff

    sym = ori_sec.obj.sym_list[stndx].link
    if sym == None:
        return None

    return (sym.obj.section[sym.shndx],sym.value + toff)

def Disasm(sec,off,base = 0):
    try:
        return sec.ins_cache[base + off]
    except KeyError:
        for ins in md.disasm(bytes(sec.data[off:]),base + off):
            if ins.address in sec.ins_cache:
                break

            relflag = False
            for idx in range(ins.address,ins.address + ins.size):
                if idx in sec.reloc:
                    relflag = True
                    break
            sec.ins_cache[ins.address] = (ins,relflag)

        if base + off in sec.ins_cache:
            return sec.ins_cache[base + off]
        else:
            sec.ins_cache[base + off] = (None,False)
            return (None,False)

def GetFin(ins,relflag):
    opfin = []
    for op in ins.operands:
        if op.type == X86_OP_REG:
            opfin.append((op.type,op.value.reg))

        elif op.type == X86_OP_MEM:
            if relflag == True:
                disp = None
            else:
                disp = op.value.mem.disp

            if op.value.mem.base in [X86_REG_RIP,X86_REG_EIP]:  #special ignore
                opfin.append([None])
            else:
                opfin.append((op.type,
                    op.value.mem.base,
                    op.value.mem.index,
                    op.value.mem.scale,
                    disp))

        elif op.type == X86_OP_IMM:
            if relflag == True:
                opfin.append((op.type,None))
            else:
                if X86_GRP_JUMP in ins.groups or X86_GRP_CALL in ins.groups:
                    opfin.append((op.type,bytes(ins.bytes)))
                else:
                    opfin.append((op.type,op.value.imm))

    return (ins.id,opfin)

def CmpFin(fina,finb):
    dis = 0
    i = 0
    for a,b in zip(fina,finb):
        i += 1
        aid,aops = a
        bid,bops = b
        if aid != bid or len(aops) != len(bops):
            dis += 1
            continue

        for aop,bop in zip(aops,bops):
            atype = aop[0]
            btype = bop[0]
            if atype == None or btype == None:
                continue
            if atype != btype:
                dis += 1
                break
            if atype == X86_OP_REG:
                if aop[1] != bop[1]:
                    dis += 1
                    break
            elif atype == X86_OP_MEM:
                if list(aop[1:3]) != list(bop[1:3]):
                    dis += 1
                    break
                if aop[4] != None and bop[4] != None and aop[4] != bop[4]:
                    dis += 1
                    break
            elif atype == X86_OP_IMM:
                if aop[1] != None and bop[1] != None and aop[1] != bop[1]:
                    dis += 1
                    break

    return dis

def FuncFin(loc,vis):
    fin = []
    while loc != None and loc not in vis:
        vis.add(loc)
        sec,off = loc
        ins,relflag = Disasm(sec,off)
        if ins == None:
            break

        fin.append(GetFin(ins,relflag))

        #print('0x%016lx %s %s'%(ins.address,ins.mnemonic,ins.op_str))
        if ins.id == X86_INS_JMP:
            loc = GetTarget(sec,ins.address + 1,ins.operands[0])

        elif ins.id == X86_INS_CALL:
            loc = sec,ins.address + ins.size
            #tloc = GetTarget(sec,ins.address + 1,ins.operands[0])
            #if tloc != None:
            #    FuncFin(tloc,vis)
            #elif ins.operands[0].type == X86_OP_IMM:
            #    print(sec.obj.name)
            #    print('0x%016lx %s %s'%(ins.address,ins.mnemonic,ins.op_str))
            #    

        elif X86_GRP_RET in ins.groups:
            loc = None

        else:
            loc = sec,ins.address + ins.size

    return fin

def gen_db(conn):
    objdic = {}

    for archobj in os.listdir('archobj'):
        name = re.findall('(.+)\.a',archobj)
        if len(name) != 1:
            continue
        name = name[0]
        try:
            os.mkdir('archobj/' + name)
        except OSError:
            pass
        
        p = subprocess.Popen(['ar','-x','../%s.a'%name],cwd = 'archobj/' + name)
        p.wait()

        for obj in os.listdir('archobj/' + name):
            objdic[obj] = OBJ('archobj/' + name + '/' + obj,obj)

    '''

    for obj in os.listdir('pthread'):
        objdic[obj] = OBJ('pthread/' + obj,obj)

    for obj in os.listdir('glib'):
        objdic[obj] = OBJ('glib/' + obj,obj)

    for obj in os.listdir('gobject'):
        objdic[obj] = OBJ('gobject/' + obj,obj)

    for obj in os.listdir('gmodule'):
        objdic[obj] = OBJ('gmodule/' + obj,obj)

    for obj in os.listdir('gio'):
        objdic[obj] = OBJ('gio/' + obj,obj)

    for obj in os.listdir('gthread'):
        objdic[obj] = OBJ('gthread/' + obj,obj)
    '''

    Resolve(objdic)

    for obj in objdic.values():
        for sym in obj.sym_export.values():
            fin = FuncFin((obj.section[sym.shndx],sym.value),set())
            finlen = len(fin)
            finbin = msgpack.packb(fin)
            finhash = hashlib.sha1(finbin).hexdigest()
            label = "%s # %s"%(obj.name,sym.name)
            print(label)

            cur = conn.execute('SELECT label FROM flowfin WHERE hash=?',
                    (finhash,))
            finent = cur.fetchone()
            if finent == None:
                conn.execute('INSERT INTO flowfin VALUES (?,?,?,?);',
                        (label,finlen,buffer(finbin),finhash))
            elif sym.name[0] != '_':
                conn.execute('UPDATE flowfin SET label=? WHERE label=?;',
                        (label,finent[0]))

    conn.commit()
