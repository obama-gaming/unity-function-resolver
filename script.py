import idc
import idaapi

def rename(address, alias):
    MakeCode(address)
    MakeFunction(address)
    MakeNameEx(address, alias, SN_NOWARN)
    return


export_function = GetOperandValue(FindBinary(0, SEARCH_DOWN, "E9 ? ? ? ? CC F2 0F 10 05 ? ? ? ?"), 0)
rename(export_function, "export_function");
    
export_xrefs = XrefsTo(export_function)
for xref in export_xrefs:
    name = GetManyBytes(GetOperandValue(xref.frm - 7, 1), 64)
    if (name.startswith("UnityEngine")):
        rename(GetOperandValue(xref.frm - 14, 1), name)
