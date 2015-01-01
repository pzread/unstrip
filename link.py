from scan import *
from mark import *

if __name__ == '__main__':
    gen_db(conn)

    '''
    db_f = open('db','rb')
    fin_db = json.load(db_f)

    exe = EXE('a','a')

    mark_list = []
    call_loc = set()

    start_pc = exe.elf.header['e_entry']
    call_loc = exe.ScanBlock(exe.GetSection(start_pc))

    main_pc = None
    finb = fin_db['libc-start.o # __libc_start_main']
    for pos,loc in call_loc:
        fina = exe.FuncFin(loc,set())
        if CmpFin(fina,finb) == 0:
            ins,_ = Disasm(pos[0],pos[1] - 7)
            main_pc = ins.operands[1].value.imm
            break

    print(hex(main_pc))
    if main_pc != None:
        mark_list.append((exe.GetSection(main_pc),'main'))
        call_loc.update(exe.ScanBlock(exe.GetSection(main_pc)))

    print(len(call_loc))
    for pos,loc in call_loc:
        fina = exe.FuncFin(loc,set())
        find_name = None
        for name,finb in fin_db.items():
            dis = CmpFin(fina,finb)
            if dis == 0:
                find_name = name
                break
        if find_name == None:
            find_name = '<unknown>'
        else:
            mark_list.append((loc,find_name.split(' # ')[1]))
        print('%016lx - %s'%(loc[0].base + loc[1],find_name))

    mark(exe,mark_list)
    '''
