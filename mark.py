import struct

def append_strtab(strtab,string):
    return (len(strtab) + 1),strtab + b'\x00' + string + b'\x00'

def mark(elf,mark_list):
    orif = open(elf.path,'rb')
    outf = open(elf.path + '.mark','wb')
    while True:
        buf = orif.read(65536)
        if len(buf) == 0:
            break
        outf.write(buf)

    if elf.elf.header['e_ident']['EI_CLASS'] == 'ELFCLASS64':
        SEK_E_SHOFF = 0x28
        SEK_E_SHNUM = 0x3C
        SEK_E_SHSTRNDX = 0x3E

        def fix_header(shoff,shnum,strndx):
            outf.seek(SEK_E_SHOFF)
            outf.write(struct.pack('Q',shoff))
            outf.seek(SEK_E_SHNUM)
            outf.write(struct.pack('H',shnum))
            outf.seek(SEK_E_SHSTRNDX)
            outf.write(struct.pack('H',strndx))

        def gen_syment(stval,shndx = None,stroff = None):
            if stval == None:
                return b'\x00' * 24
            return struct.pack('IBBHQQ',stroff,0x12,0,shndx,stval,0x0)

        def gen_strtabent(off,size,stroff):
            return struct.pack('IIQQQQIIQQ',stroff,3,0,0,off,size,0,0,1,0)

        def gen_symtabent(off,size,strndx,stroff):
            return struct.pack('IIQQQQIIQQ',stroff,2,0,0,off,size,strndx,0,8,24)

    strtab = elf.elf.get_section(elf.elf.header['e_shstrndx']).data()
    stroff_strtab,strtab = append_strtab(strtab,'.strtab')
    stroff_symtab,strtab = append_strtab(strtab,'.symtab')
    symtab = gen_syment(None)
    for loc,name in mark_list:
        stroff,strtab = append_strtab(strtab,name)
        symtab += gen_syment(loc[0].base + loc[1],loc[0].idx,stroff)

    strtab_off = outf.tell()
    outf.write(strtab)
    symtab_off = outf.tell()
    outf.write(symtab)

    sec_off = outf.tell()
    orif.seek(elf.elf.header['e_shoff'])
    buf = orif.read(elf.elf.header['e_shnum'] * elf.elf.header['e_shentsize'])
    outf.seek(sec_off)
    outf.write(buf)
    strndx = elf.elf.header['e_shnum']
    outf.write(gen_strtabent(strtab_off,len(strtab),stroff_strtab))
    outf.write(gen_symtabent(symtab_off,len(symtab),strndx,stroff_symtab))

    fix_header(sec_off,elf.elf.header['e_shnum'] + 2,strndx)

    orif.close()
    outf.close()
