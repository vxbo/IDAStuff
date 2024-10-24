# ; <===================================>
# ; WRITTEN BY VXBO
# ; <===================================>
# ; 
# ; This  file contains a collection  of
# ; prewritten  analysis,  visualization
# ; and utility  functions with the  use
# ; of IDAPython and external libraries.
# ; 
# ; <===================================>
# ; Licensed under The Unlicense license.
# ; See LICENSE.txt in the project root
# ; for full information.
# ; <===================================>


# ; <========================>
# ; TODO: add doxygen comments
# ; <========================>


# ; <=====================================>
# ; IMPORT SECTION START
# ; <=====================================>
from typing import List, Tuple, Union, Optional
import idaapi, idautils, idc          # type: ignore
# ; <=====================================>
# ; IMPORT SECTION END
# ; <=====================================>

# ; <=====================================>
# ; CONSTANT GLOBAL VARIABLES SECTION START
# ; <=====================================>
BASEADDR = idaapi.get_imagebase()
# ; <=====================================>
# ; CONSTANT GLOBAL VARIABLES SECTION END
# ; <=====================================>

# ; <=====================================>
# ; FUNCTION SECTION START
# ; <=====================================>
def make_namespace(enum_name: str, entries: List[Tuple[str, Union[str, int]]], file) -> None:
    file.write("namespace {} {\n".format(enum_name))

    for name, value in entries:
        if not name: continue
        fnc_value = value if value != -1 else 0x0
        is_mismatch = fnc_value == idaapi.BADADDR or fnc_value == 0

        if isinstance(value, str):
            file.write(f"   constexpr std::uint32_t {name} = {value};\n")
            continue

        if fnc_value >= BASEADDR and not is_mismatch:
            idc.set_name(fnc_value, name)
            fnc_value -= BASEADDR

        comment = "// broken pattern" if is_mismatch else ""
        file.write("   constexpr std::uint32_t %s{ %s }; %s\n" % (name, hex(fnc_value), comment))

    file.write("};\n")

def find_function_by_pattern(pattern: str) -> int:
    address = idc.find_binary(0, 1, pattern)
    if address != idaapi.BADADDR:
        function = idaapi.get_func(address)
    return address if address == idaapi.BADADDR else function.start_ea if function else idaapi.BADADDR

def find_offset_by_string(name: str, offset: int, op_value: int) -> int:
    address = idc.find_binary(0, 1, f"\"{name}\"")
    if address == idaapi.BADADDR:
        return idaapi.BADADDR

    for xref in idautils.XrefsTo(address):
        dword = xref.frm + offset
        return idc.get_operand_value(dword, op_value) if dword != idaapi.BADADDR else idaapi.BADADDR

    return idaapi.BADADDR

def find_function_call(pattern: str) -> int:
    address = idc.find_binary(0, 1, pattern)
    return idc.get_operand_value(address, 0) if address != idaapi.BADADDR else 0

def get_function_name(address: int) -> Optional[str]:
    function = idaapi.get_func(address)
    return idc.get_name(function.start_ea) if function else None

def get_function_parameters(address: int) -> List[str]:
    function = idaapi.get_func(address)
    if not function: return []

    paramc = idc.get_func_attr(function.start_ea, idc.FUNC_PARAM_COUNT)
    return [idc.get_struc_member_name(function.start_ea, i) for i in range(paramc) if idc.get_struc_member_name(function.start_ea, i)]

def get_function_return_type(address: int) -> str:
    function = idaapi.get_func(address)
    return idc.get_type(function.start_ea) if function else ""

def get_all_functions() -> List[Tuple[str, int]]:
    return [(idc.get_name(function.start_ea), function.start_ea) for function in idaapi.get_functions()]

def search_function_by_name(name: str) -> int:
    for function in idaapi.get_functions():
        if name in idc.get_name(function.start_ea):
            return function.start_ea
    return idaapi.BADADDR

def get_function_size(address: int) -> int:
    function = idaapi.get_func(address)
    return function.size() if function else 0

def get_function_instructions(address: int) -> List[str]:
    function = idaapi.get_func(address)
    return [idc.GetDisasm(head) for head in idautils.Heads(function.start_ea, function.end_ea)]

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
    if not function: return []
    return [idc.get_struc_member_name(function.start_ea, i) for i in range(idc.get_func_attr(function.start_ea, idc.FUNC_LOCAL)) if idc.get_struc_member_name(function.start_ea, i)]

def get_function_stack_size(address: int) -> int:
    function = idaapi.get_func(address)
    return idc.get_func_attr(function.start_ea, idc.FUNC_FRSIZE) if function else 0

def get_function_cyclomatic_complexity(address: int) -> int:
    function = idaapi.get_func(address)
    if not function: return 0

    complexity = 1
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            insn = idautils.DecodeInstruction(head)
            if insn:
                if insn.itype in [idaapi.NN_jmp, idaapi.NN_jmpf, idaapi.NN_call, idaapi.NN_callf]:
                    complexity += 1
    return complexity

def get_function_instruction_cout(address: int) -> int:
    function = idaapi.get_func(address)
    return sum(1 for head in idautils.Heads(function.start_ea, function.end_ea)) if function else 0

def get_function_basic_blocks(address: int) -> List[Tuple[int, int]]:
    function = idaapi.get_func(address)
    blocks = []

    if function:
        cur_block_start = None
        for head in idautils.Heads(function.start_ea, function.end_ea):
            if idc.is_code(idc.getFlags(head)):
                if cur_block_start is None:
                    cur_block_start = head
            else:
                if cur_block_start is not None:
                    blocks.append((cur_block_start, head))
                    cur_block_start = None

            if cur_block_start is not None:
                blocks.append((cur_block_start, function.end_ea))
    return blocks

def if_function_recursive(address: int, visited: Optional[set] = None) -> bool:
    if visited is None:
        visited = set()

    if address in visited:
        return False
    visited.add(address)

    for _, caller_address in get_function_callers(address):
        if caller_address == address or if_function_recursive(caller_address, visited):
            return True
    return False

def get_function_mem_accesses(address: int) -> List[str]:
    function = idaapi.get_func(address)
    accesses = set()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            if idc.is_code(idc.getFlags(head)):
                insn = idautils.DecodeInstruction(head)
                if insn and insn.type in [idaapi.NN_mov, idaapi.NN_push, idaapi.NN_pop]:
                        accesses.add(f"Instruction at {head}: {idc.GetDisasm(head)}")
    return list(accesses)

def get_function_mem_usage(address: int) -> int:
    function = idaapi.get_func(address)
    return function.size() + get_function_stack_size(address) if function else 0

def compare_functions(address1: int, address2: int) -> float:
    return __import__("difflib").SequenceMatcher(None, get_function_instructions(address1), get_function_instructions(address2)).ratio()

def visualize_function_control_flow_graph(address: int) -> None:
    import networkx as nx           # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    graph = nx.DiGraph()
    for head in idautils.Heads(function.start_ea, function.end_ea):
        graph.add_node(str(head), idc.GetDisasm(head))
        for xref in idautils.XrefsFrom(head):
            graph.add_edge(str(head), str(xref.to))

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightred", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, 'weight'))
    plt.title("Function Control Flow Graph")
    plt.show()

def visualize_function_call_graph(address: int) -> None:
    import networkx as nx           # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    graph = nx.DiGraph()
    for callee_name, _ in get_function_callees(address):
        graph.add_edge(get_function_name(address), callee_name)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, 'weight'))
    plt.title("Function Call Graph")
    plt.show()

def visualize_enhanced_function_call_graph(address: int) -> None:
    import networkx as nx           # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    graph = nx.DiGraph()
    for callee_name, callee_address in get_function_callees(address):
        call_freq = analyze_function_call_frequency(callee_address)
        graph.add_edge(get_function_name(address), callee_name, weight=call_freq[callee_address])

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, 'weight'))
    plt.title("Enhanced Function Call Graph")
    plt.show()

def visualize_function_call_patterns(address: int) -> None:
    import networkx as nx           # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    graph = nx.DiGraph()
    for callee_name, _ in get_function_callees(address):
        graph.add_edge(get_function_name(address), callee_name)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightgreen", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, "weight"))
    plt.title("Function Call Patterns")
    plt.show()

def visualize_function_dependencies(address: int) -> None:
    import networkx as nx           # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    graph = nx.DiGraph()
    for callee_name, _ in get_function_callees(address):
        graph.add_edge(get_function_name(address), callee_name)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels = True, node_size=3000, node_color="lightgreen", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, "weight"))
    plt.title(f"Function Dependency Graph for {get_function_name(address)}")
    plt.show()

def generate_functions_similarity_heatmap(threshold: float) -> None:
    import seaborn as sb            # type: ignore
    import matplotlib.pyplot as plt # type: ignore
    import numpy as np              # type: ignore

    functions = get_all_functions()
    if functions == []: return

    sim_matrix = np.zeros((len(functions), len(functions)))
    for i, (_, address1) in enumerate(functions):
        for j, (_, address2) in enumerate(functions):
            if i != j:
                sim = compare_functions(address1, address2)
                sim_matrix[i][j] = sim if sim > threshold else 0

    sb.heatmap(sim_matrix, xticklabels=[name for name, _ in functions], yticklabels=[name for name, _ in functions])
    plt.title("Function Similarity Heatmap")
    plt.show()

def visualize_function_complexity(address: int) -> None:
    import seaborn as sb            # type: ignore
    import matplotlib.pyplot as plt # type: ignore

    function = idaapi.get_func(address)
    if not function: return

    complexity_map = list()
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            complexity = get_function_cyclomatic_complexity(head)
            complexity_map.append(complexity)

    sb.heatmap([complexity_map], cmap="YlGnBu")
    plt.title(f"Cyclomatic Complexity Heatmap for {get_function_name(address)}")
    plt.xlabel("Instructions")
    plt.ylabel("Complexity")
    plt.show()

def cluster_functions(threshold: float) -> List[List[int]]:
    functions = get_all_functions()
    clusters = []

    for i, (_, address1) in enumerate(functions):
        cluster = [address1]
        for j, (_, address2) in enumerate(functions):
            if i != j and compare_functions(address1, address2) > threshold:
                cluster.append(address2)
        clusters.append(cluster)
    return clusters

def recognize_instruction_patterns(address: int) -> dict:
    function = idaapi.get_func(address)
    patterns = {}

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            insn = idautils.DecodeInstruction(head)
            if insn:
                pattern = f"{insn.itype}:{insn.Op1.type}:{insn.Op2.type}"
                patterns[pattern] = patterns.get(pattern, 0) + 1
        return patterns

def analyze_function_call_frequency(address: int) -> dict:
    function = idaapi.get_func(address)
    call_freq = {}

    callees = get_function_callees(function.start_ea)
    call_freq[function.start_ea] = len(callees)

    return call_freq

def get_function_referenced_variables(address: int) -> List[str]:
    function = idaapi.get_func(address)
    if not function: return []

    ref_vars = set()
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            for op in range(idc.get_opnd_count(head)):
                operand = idc.get_operand_value(head, op)
                var_name = idc.get_name(operand)
                if var_name and var_name not in ref_vars:
                    ref_vars.add(var_name)
    return list(ref_vars)

def find_unused_functions() -> List[str]:
    functions = get_all_functions()
    used_functions = set()

    for _, address in functions:
        callees = get_function_callees(address)
        for callee_name, _ in callees:
            used_functions.add(callee_name)
    return [name for name, _ in functions if name not in used_functions]

def detect_function_anomalies(threshold: int = 5) -> List[str]:
    functions = get_all_functions()
    anomalies = []

    for name, address in functions:
        complexity = get_function_cyclomatic_complexity(address)
        size = get_function_size(address)
        if complexity > threshold or size > threshold * 100: # Arbitrary size threshold
            anomalies.append(name)
    return anomalies

def get_function_call_depth(address: int) -> int:
    def helper(addr: int, depth: int) -> int:
        callees = get_function_callees(addr)
        if not callees:
            return depth
        return max(helper(callee_address, depth+1) for _, callee_address in callees)

    return helper(address, 1)

def get_function_str_literals(address: int) -> List[str]:
    function = idaapi.get_func(address)
    strlit = set()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            for op in range(idc.get_opnd_count(head)):
                operand = idc.get_operand_value(head, op)
                if idc.get_type(operand) == "string":
                    strlit.add(idc.get_strlit_contents(operand))
    return list(strlit)

def get_function_inlining_candidates(threshold: int) -> List[Tuple[str, int]]:
    candidates = set()

    for name, address in get_all_functions():
        size = get_function_size(address)
        if size < threshold:
            candidates.add((name, address))
    return list(candidates)

def analyze_function_branching(address: int) -> dict:
    function = idaapi.get_func(address)
    stats = {"total_branches": 0, "conditional_branches": 0, "unconditional_branches": 0}

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            if idc.is_code(idc.getFlags(head)):
                insn = idautils.DecodeInstruction(head)
                if insn:
                    if insn.itype in [idaapi.NN_jmp, idaapi.NN_jmpf]:
                        stats["total_branches"] += 1
                        stats["unconditional_branches"] += 1
                    elif insn.itype in [idaapi.NN_je, idaapi.NN_jne, idaapi.NN_jg, idaapi.NN_jge, idaapi.NN_jl, idaapi.jle, idaapi.NN_jb, idaapi.NN_jbe]:
                        stats["total_branches"] += 1
                        stats["conditional_branches"] += 1
    return stats

def get_function_hotspots(address: int, threshold: int = 5) -> List[Tuple[int, str]]:
    function = idaapi.get_func(address)
    hotspots = dict()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            if idc.is_code(idc.getFlags(head)):
                if idautils.DecodeInstruction(head):
                    hotspots[head] = hotspots.get(head, 0) + 1
    return [(addr, idc.GetDisasm(addr)) for addr, count in hotspots.items() if count >= threshold]

def detect_dead_code() -> List[Tuple[str, int]]:
    functions = get_all_functions()
    called = set()

    for name, address in functions:
        for callee_name, _ in get_function_callees(address):
            called.add(callee_name)
    return [(name, address) for name, address in functions if name not in called]
# ; <=====================================>
# ; FUNCTION SECTION END
# ; <=====================================>

# <<<<<<<<<<<<<<<<<<<EOF>>>>>>>>>>>>>>>>>>>