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

def search_function_by_name(name: str) -> int:
    for function in idaapi.get_functions():
        if name in idc.get_name(function.start_ea):
            return function.start_ea
    return idaapi.BADADDR

def get_function_details(address: int) -> dict:
    function = idaapi.get_func(address)
    if function:
        return {
            "name": idc.get_name(function.start_ea),
            "parameters": get_function_parameters(address),
            "return_type": get_function_return_type(address)
        }
    return {}

def get_function_size(address: int) -> int:
    function = idaapi.get_func(address)
    return function.size() if function else 0

def get_function_instructions(address: int) -> List[str]:
    function = idaapi.get_func(address)
    instructions = []

    for head in idautils.Heads(function.start_ea, function.end_ea):
        instructions.append(idc.GetDisasm(head))
    return instructions

def rename_function(address: int, new_name: str) -> bool:
    function = idaapi.get_func(address)
    if function:
        idc.set_name(function.start_ea, new_name)
        return True
    return False

def get_function_callers(address: int) -> List[Tuple[str, int]]:
    callers = []
    for xref in idautils.XrefsTo(address):
        caller_address = xref.frm
        caller_function = idaapi.get_func(caller_address)
        if caller_function:
            caller_name = get_function_name(caller_function.start_ea)
            callers.append((caller_name, caller_address))
    return callers

def get_function_callees(address: int) -> List[Tuple[str, int]]:
    callees = []
    function = idaapi.get_func(address)
    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            for xref in idautils.XrefsFrom(head):
                callee_address = xref.to
                callee_function = idaapi.get_func(callee_address)
                if callee_function:
                    callee_name = idc.get_name(callee_function.start_ea)
                    callees.append((callee_name, callee_address))
    return callees

def get_function_comment(address: int) -> str:
    function = idaapi.get_func(address)
    return idc.get_func_cmt(function.start_ea, 0) if function else ""

def set_function_comment(address: int, comment: str) -> bool:
    function = idaapi.get_func(address)
    if function:
        idc.set_func_cmt(function.start_ea, comment, 0)
        return True
    return False

def get_function_calling_convention(address: int) -> str:
    function = idaapi.get_func(address)
    return idc.get_func_cc(function.start_ea) if function else ""

def get_function_local_variables(address: int) -> List[str]:
    function = idaapi.get_func(address)
    if not function:
        return []

    local_vars = []
    for i in range(idc.get_func_attr(function.start_ea, idc.FUNC_LOCAL)):
        local_var_name = idc.get_struc_member_name(function.start_ea, i)
        if local_var_name:
            local_vars.append(local_var_name)
    return local_vars

def get_function_stack_size(address: int) -> int:
    function = idaapi.get_func(address)
    return idc.get_func_attr(function.start_ea, idc.FUNC_FRSIZE) if function else 0

def get_function_cyclomatic_complexity(address: int) -> int:
    function = idaapi.get_func(address)
    if not function:
        return 0
    
    complexity = 1
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            insn = idautils.DecodeInstruction(head)
            if insn:
                if insn.itype in [idaapi.NN_jmp, idaapi.NN_jmpf, idaapi.NN_call, idaapi.NN_callf]:
                    complexity += 1
    return complexity