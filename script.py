import idc
import idaapi

def set_name(address, alias):
    MakeNameEx(address, alias, SN_NOWARN)

def find_function(sig, name, operand):
    address = GetOperandValue(FindBinary(0, SEARCH_DOWN, sig), operand)
    set_name(address, name)
    return address

def resolve(function, prefix, callback):
    xrefs = XrefsTo(function)
    for xref in xrefs:
        counter = 0;
        while (counter < 20):
            name = GetManyBytes(GetOperandValue(xref.frm - counter, 1), 64)
            if (name.startswith(prefix)):
                callback(xref.frm, name)
                break           
            counter += 1

def import_callback(address, name):
    set_name(GetOperandValue(address + 5, 0), name)

def export_callback(address, name):
    set_name(GetOperandValue(address - 14, 1), name)

exports = find_function("E9 ? ? ? ? CC F2 0F 10 05 ? ? ? ?", "find_export", 0)
resolve(exports, "UnityEngine", export_callback)

imports = find_function("E8 ? ? ? ? 48 8B 0E 48 89 01", "find_import", 0)
resolve(imports, "il2cpp", import_callback)
