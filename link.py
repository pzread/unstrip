import sys
import sqlite3
import msgpack
from scan import *
from mark import *

if __name__ == '__main__':
    conn = sqlite3.connect('fin.db')
    try:
        conn.execute('CREATE TABLE flowfin (label text primary key,len int,fin blob);')
        conn.execute('CREATE INDEX index_flowfin_len ON flowfin (len);')
    except sqlite3.OperationalError:
        pass

    gen_db(conn)

    filepath = sys.argv[1]
    exe = EXE(filepath,filepath)

    mark_list = []
    call_loc = set()

    start_pc = exe.elf.header['e_entry']
    call_loc = exe.ScanBlock(exe.GetSection(start_pc))

    main_pc = None
    cur = conn.cursor()
    cur.execute('SELECT * FROM flowfin WHERE label=?;',
            ('libc-start.o # __libc_start_main',))
    finent = cur.fetchone()
    if finent != None:
        finb = msgpack.unpackb(finent[2])
        for pos,loc in call_loc:
            fina = exe.FuncFin(loc,set())
            if CmpFin(fina,finb) == 0:
                ins,_ = Disasm(pos[0],pos[1] - 7)
                main_pc = ins.operands[1].value.imm
                break

    if main_pc != None:
        mark_list.append((exe.GetSection(main_pc),'main'))
        call_loc.update(exe.ScanBlock(exe.GetSection(main_pc)))

    for pos,loc in call_loc:
        fina = exe.FuncFin(loc,set())
        find_name = None

        for row in conn.execute('SELECT * FROM flowfin WHERE len<=?;',
                (len(fina),)):
            finb = msgpack.unpackb(row[2])
            dis = CmpFin(fina,finb)
            if dis == 0:
                find_name = row[0]
                break
        if find_name == None:
            find_name = '<unknown>'
        else:
            mark_list.append((loc,find_name.split(' # ')[1]))
        print('%016lx - %s'%(loc[0].base + loc[1],find_name))

    mark(exe,mark_list)
