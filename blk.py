from idaapi import *
from idautils import *
from idc import *
import sys
import json
import base64

def main():
    funclist = list()
    for segea in Segments():
        seg = getseg(segea)
        func = get_next_func(seg.startEA)
        while func is not None and func.startEA < seg.endEA:
            name = GetFunctionName(func.startEA)

            fc = FlowChart(func)
            bblist = list()
            for bb in fc:
                succs = map(lambda x: x.startEA,bb.succs())
                code = GetManyBytes(bb.startEA,bb.endEA - bb.startEA)
                if code == None:
                    code = b''
                bblist.append({
                    'offset':bb.startEA,
                    'size':bb.endEA - bb.startEA,
                    'succ':succs,
                    'mode':GetReg(bb.startEA,'T'),
                    'code':base64.b64encode(code)
                })
            funclist.append({
                'name':name,
                'offset':func.startEA,
                'bb':bblist
            })

            func = get_next_func(func.startEA)

    open(get_root_filename() + '.json','w').write(json.dumps(funclist))

if __name__=='__main__':
    idaapi.autoWait()
    main()
    idc.Exit(0)
