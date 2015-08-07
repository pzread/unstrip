import sys
import re
import os
import subprocess
import collections
import json
import binascii
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *

FILE = sys.argv[1]
ARCH = CS_ARCH_ARM
if ARCH == CS_MODE_64:
    md = Cs(CS_ARCH_X86,CS_MODE_64)
elif ARCH == CS_ARCH_ARM:
    md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
md.detail = True

class R2Com:
    def __init__(self,path):
        if ARCH == CS_MODE_64:
            archopt = 'x64'
            bits = 64
        elif ARCH == CS_ARCH_ARM:
            archopt = 'arm'
            bits = 16

        self.p = subprocess.Popen(['r2','-q0','-a',archopt,'-b','%d'%bits,'-e','anal.depth=256','-A',path],stdin = subprocess.PIPE,stdout = subprocess.PIPE)
        self.p.stdout.read(1)

    def cmdj(self,cmd):
        self.p.stdin.write(bytes(cmd + '\n','utf-8'))
        self.p.stdin.flush()
        ret = bytearray()
        while True:
            data = os.read(self.p.stdout.fileno(),65536)
            if len(data) == 0:
                return None
            if data[-1] == 0:
                ret += data[:-1]
                if len(ret) == 0:
                    return None
                return json.loads(ret.decode('utf-8'))
            ret += data

    def cmd(self,cmd):
        self.p.stdin.write(bytes(cmd + '\n','utf-8'))
        self.p.stdin.flush()
        ret = bytearray()
        while True:
            data = os.read(self.p.stdout.fileno(),65536)
            if len(data) == 0:
                return None
            if data[-1] == 0:
                ret += data[:-1]
                if len(ret) == 0:
                    return None
                return ret.decode('utf-8')
            ret += data

class Fin:
    def __init__(self,path):
        self.path = path
        self.r2 = R2Com(path)
        self.r2.cmd('aaa')

    def fin_operand_x86(self,ods):
        odfin = list()
        for od in ods:
            if od.type == X86_OP_REG:
                odfin.append((od.type,od.value.reg))

            elif od.type == X86_OP_MEM:
                odfin.append((od.type,
                    od.value.mem.base,
                    od.value.mem.index,
                    od.value.mem.scale,
                    od.value.mem.disp))

            elif od.type == X86_OP_IMM:
                odfin.append((od.type,od.value.imm))

        return odfin

    def fin_operand_arm(self,ods):
        odfin = list()
        for od in ods:
            if od.type == ARM_OP_REG:
                odfin.append((od.type,od.value.reg))

            elif od.type == ARM_OP_MEM:
                odfin.append((od.type,
                    od.value.mem.base,
                    od.value.mem.index,
                    od.value.mem.scale,
                    od.value.mem.disp))

            elif od.type == ARM_OP_IMM:
                odfin.append((od.type,od.value.imm))

            else:
                odfin.append([od.type])

        return odfin

    def fin_ins(self,ins):
        if ARCH == CS_MODE_32 or ARCH == CS_MODE_64:
            odfin = self.fin_operand_x86(ins.operands)
        elif ARCH == CS_ARCH_ARM:
            odfin = self.fin_operand_arm(ins.operands)
        return (ins.id,odfin)

    def fin_blk(self,blk):
        ops = blk['ops']
        opfin = list()
        for op in ops:
            typ = op['type']
            if typ == 'invalid':
                continue

            if ARCH == CS_ARCH_ARM:
                if len(op['bytes']) == 2:
                    md.mode = CS_MODE_THUMB
                else:
                    md.mode = CS_MODE_ARM

            for ins in md.disasm(binascii.unhexlify(op['bytes']),0x0):
                opfin.append(self.fin_ins(ins))

        return opfin

    def get_elf_funclist(self):
        return list(filter(lambda x: x['type'] == 'fcn' or x['type'] == 'sym',self.r2.cmdj('aflj')))

    def get_sym_funclist(self):
        funcstr = self.r2.cmd('is~FUNC')
        for line in funcstr.split('\n')[:-1]:
            part = re.findall('vaddr=0x(.+) paddr=0x(.+) ord=(.+) fwd=(.+) sz=(.+) bind=(.+) type=(.+) name=(.+)',line)[0]
            if part[6] != 'FUNC':
                continue
            self.r2.cmd('afr@%d'%int(part[1],16))

        self.r2.cmd('aaa')

        return list(filter(lambda x: x['type'] == 'sym',self.r2.cmdj('aflj')))
        
    def gen_fin(self,funclist):
        funcfin = dict()
        for func in funclist:
            print(func['name'])

            cfgs = self.r2.cmdj('agj %d'%func['offset'])
            if len(cfgs) == 0 or len(cfgs) > 1:
                continue
            cfg = cfgs[0]
            blocks = cfg['blocks']
            blkdic = dict()
            for blk in blocks:
                blkdic[blk['offset']] = blk

            blkfin = list()
            blkvis = set()
            worklist = collections.deque()
            worklist.append(func['offset'])
            while len(worklist) > 0:
                addr = worklist.popleft()
                if addr in blkvis:
                    continue
                if addr not in blkdic:
                    continue   
                blkvis.add(addr)
                blk = blkdic[addr]
                print(blk)
                if 'jump' in blk:
                    worklist.append(blk['jump'])
                if 'fail' in blk:
                    worklist.append(blk['fail'])
                blkfin.append(self.fin_blk(blk))

            funcfin[func['name']] = blkfin

        return funcfin

fin = Fin(FILE)

#funclist = fin.get_sym_funclist()
funclist = fin.get_elf_funclist()

funcfins = fin.gen_fin(filter(lambda x: x['name'] == 'sym.close',funclist))
open('snapper-arm.json','w').write(json.dumps(funcfins))

print(len(funclist))
