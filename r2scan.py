import re
import os
import subprocess
import collections
import json
import binascii
from capstone import *
from capstone.x86_const import *

ARCH = CS_MODE_64
if ARCH == CS_MODE_64:
    md = Cs(CS_ARCH_X86,CS_MODE_64)
md.detail = True

class R2Com:
    def __init__(self,path):
        self.p = subprocess.Popen(['r2','-q0',path],stdin = subprocess.PIPE,stdout = subprocess.PIPE)
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

class Fin():
    def __init__(self,path):
        self.path = path
        self.r2 = R2Com(path)
        self.r2.cmdj('aa')

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

    def fin_ins(self,ins):
        if ARCH == CS_MODE_32 or ARCH == CS_MODE_64:
            odfin = fin_operand_x86(ins.operands)
        return (ins.id,odfin)

    def fin_blk(self,blk):
        ops = blk['ops']
        opfin = list()
        for op in ops:
            typ = op['type']
            if typ == 'invalid':
                continue
            for ins in md.disasm(binascii.unhexlify(op['bytes']),0x0):
                opfin.append(fin_ins(ins))
        return opfin

    def get_funclist(self):
        funcstr = self.r2.cmd('is~FUNC')
        funcs = list()
        for line in funcstr.split('\n')[:-1]:
            part = re.findall('vaddr=0x(.+) paddr=0x(.+) ord=(.+) fwd=(.+) sz=(.+) bind=(.+) type=(.+) name=(.+)',line)[0]
            if part[6] != 'FUNC':
                continue
            funcs.append({
                'name':part[7],    
                'offset':int(part[0],16)
            })

        return funcs

    def gen_fin(self):
        funcfin = dict()
        for func in get_funclist():
            print(func['name'])

            cfgs = self.r2.cmdj('agj %d'%func['offset'])
            if len(cfgs) == 0:
                continue
            assert(len(cfgs) == 1)

            for cfg in cfgs:
                blocks = cfg['blocks']
                blkdic = dict()
                for blk in cfg['blocks']:
                    blkdic[blk['offset']] = blk

                worklist = collections.deque()
                worklist.append(cfg['offset'])
                blkfin = dict()
                while len(worklist) > 0:
                    addr = worklist.popleft()
                    if addr in blkfin:
                        continue
                    if addr not in blkdic:
                        continue
                    blk = blkdic[addr]

                    if 'jump' in blk:
                        worklist.append(blk['jump'])
                    if 'fail' in blk:
                        worklist.append(blk['fail'])

                    blkfin[addr] = fin_blk(blk)

            funcfin[func['offset']] = (func['name'],blkfin)

        print(len(funcfin))
        open(path + '.findump','w').write(json.dumps(funcfin))

gen_fin('libc.so.6-1')
