import sys
import re
import os
import subprocess
import collections
import json
import binascii
import base64
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *

ARCH = CS_ARCH_ARM
#MODE = CS_MODE_64
if ARCH == CS_ARCH_X86:
    md = Cs(CS_ARCH_X86,MODE)
elif ARCH == CS_ARCH_ARM:
    md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
md.detail = True

class Fin:
    def __init__(self,path):
        self.path = path

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
        md.mode = blk['mode']
        opfin = list()
        for ins in md.disasm(blk['code'],0x0):
            opfin.append(self.fin_ins(ins))
        return opfin

    def get_elf_funclist(self):
        return json.loads(open(self.path,'r').read())

    def get_sym_funclist(self):
        return list(filter(lambda x: not x['name'].startswith('sub_'),json.loads(open(self.path,'r').read())))

    def gen_fin(self,funclist):
        funcfin = dict()
        for func in funclist:
            name = func['name']
            print(name)

            blkdic = {}
            for blk in func['bb']:
                blk['code'] = base64.b64decode(blk['code'])
                if ARCH == CS_ARCH_X86:
                    blk['mode'] = MODE
                elif ARCH == CS_ARCH_ARM:
                    if blk['mode'] == 1:
                        blk['mode'] = CS_MODE_THUMB
                    else:
                        blk['mode'] = CS_MODE_ARM

                blkdic[blk['offset']] = blk

            blkfin = list()
            blkvis = set()
            worklist = collections.deque()
            worklist.append(func['offset'])
            while len(worklist) > 0:
                addr = worklist.popleft()
                if addr in blkvis:
                    continue
                blkvis.add(addr)
                blk = blkdic[addr]

                succ = list(blk['succ'])
                succ.sort()
                worklist.extend(succ)

                blkfin.append(self.fin_blk(blk))
            
            funcfin[func['name']] = (func['offset'],blkfin)

        return funcfin

'''
mergefin = dict()
for FILE in sys.argv[1:]:
    print(FILE)
    fin = Fin(FILE)
    funcfin = fin.gen_fin(fin.get_sym_funclist())
    mergefin.update(funcfin)

open('merge.fin','w').write(json.dumps(mergefin))
print(len(mergefin))
'''

FILE = sys.argv[1]
fin = Fin(FILE)
funcfin = fin.gen_fin(fin.get_elf_funclist())

open(FILE + '.fin','w').write(json.dumps(funcfin))
print(len(funcfin))
