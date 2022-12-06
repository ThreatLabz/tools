# add removed stack strings as comments

import json

import idaapi


def set_hexrays_comment(ea, comment):
    cfunc = idaapi.decompile(ea)
    eamap = cfunc.get_eamap()
    eamap_ea = eamap[ea][0].ea
    tl = idaapi.treeloc_t()
    tl.ea = eamap_ea
    comment_set = False
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp 
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            comment_set = True
            cfunc.save_user_cmts()
            break
            
        cfunc.del_orphan_cmts()
        
    return comment_set


fp = open("comment_mapping.json", "r")
data = fp.read()
fp.close()
comment_mapping = json.loads(data)

for ea_str, comment in comment_mapping.items():
    ea = int(ea_str)
    
    print(f"setting comment {comment} at 0x{ea:x}")
    try:
        if not set_hexrays_comment(ea, comment):
            print(f"couldn't set comment")
    except Exception as err:
        print(f"couldn't set comment: {err}")
