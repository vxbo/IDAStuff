from typing import List, Tuple, Union, Optional
import idaapi, idc, idautils

BASEADDR = idaapi.get_imagebase()

def make_namespace(enum_name: str, entries: List[Tuple[str, Union[str, int]]], file) -> None:
    file.write("namespace {} {\n".format(enum_name))

    for name, value in entries:
        if not name: continue

        if isinstance(value, str):
            file.write(f"   constexpr std::uint32_t {name} = {value};\n")
            continue

        fnc_value = value if value != -1 else 0x0
        is_mismatch = fnc_value == idaapi.BADADDR or fnc_value == 0

        if fnc_value >= BASEADDR and not is_mismatch:
            idc.set_name(fnc_value, name)
            fnc_value -= BASEADDR
        
        comment = "// broken pattern" if is_mismatch else ""
        file.write("   constexpr std::uint32_t %s{ 0x%s:X }; %s\n" % (name, fnc_value, comment))
    
    file.write("};\n")

def find_function_by_pattern(pattern: str) -> int:
    address = idc.find_binary(0, 1, pattern)
    if address == idaapi.BADADDR:
        return idaapi.BADADDR
    return idaapi.get_func(address).start_ea if idaapi.get_func(address) else idaapi.BADADDR

def find_offset_by_string(name: str, offset: int, op_value: int) -> int:
    address = idc.find_binary(0, 1, f"\"{name}\"")
    if address == idaapi.BADADDR:
        return idaapi.BADADDR
    
    xrefs = idautils.XrefsTo(address)
    for xref in xrefs:
        dword = xref.frm + offset
        return idc.get_operand_value(dword, op_value) if dword != idaapi.BADADDR else idaapi.BADADDR
    
    return idaapi.BADADDR

def find_function_call(pattern: str) -> int:
    address = idc.find_binary(0, 1, pattern)
    return idc.get_operand_value(address, 0) if address != idaapi.BADADDR else 0

def get_function_name(address: int) -> Optional[str]:
    function = idaapi.get_func(address)
    if function:
        return idc.get_name(function.start_ea)
    return None

def get_function_parameters(address: int) -> List[str]:
    function = idaapi.get_func(address)
    if not function:
        return []
    
    paramc = idc.get_func_attr(function.start_ea, idc.FUNC_PARAM_COUNT)
    params = []
    
    for i in range(paramc):
        param_name = idc.get_struc_member_name(function.start_ea, i)
        if param_name:
            params.append(param_name)
    
    return params

def get_function_return_type(address: int) -> str:
    function = idaapi.get_func(address)
    if function:
        return idc.get_type(function.start_ea)
    return ""

def get_all_functions() -> List[Tuple[str, int]]:
    functions = []
    for function in idaapi.get_functions():
        name = idc.get_name(function.start_ea)
        functions.append((name, function.start_ea))
    return functions