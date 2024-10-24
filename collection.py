# ; <===================================>
# ; WRITTEN BY VXBO
# ; <===================================>
# ; 
# ; This  file contains a collection  of
# ; prewritten  analysis,  visualization
# ; and  utility functions with the  use
# ; of IDAPython and external libraries.
# ; 
# ; <===================================>
# ; Licensed under The Unlicense license.
# ; See LICENSE.txt in the project root
# ; for full information.
# ; <===================================>



# ; <=====================================>
# ; IMPORT SECTION START
# ; <=====================================>
from typing import List, Dict, Tuple, Union, Optional
import idaapi, idautils, idc          # type: ignore
import networkx as nx                 # type: ignore
import matplotlib.pyplot as plt       # type: ignore
import seaborn as sb                  # type: ignore
import numpy as np                    # type: ignore
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
    """
    @brief Generates a C++ namespace with a set of named constants and
           their corresponding values.


    @param enum_name The name of the namespace to generate.
    @param entries A list of tuples, where each tuple contains a name and a value.
                   The value can be either an integer or a string.
    @param file The file object to write the generated code to.

    @warning This function modifies the IDA database by setting names for addresses
             that are within the database.
    """
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
    """
    @brief Searches for a binary pattern in the loaded binary and returns the
           starting address of the function that contains the pattern.


    @param pattern A string representing the binary pattern to search for.

    @return The starting address of the function containing the pattern if found; 
            otherwise, returns idaapi.BADADDR.

    @note This function utilizes the IDA Pro API to find the binary pattern and retrieve the corresponding function.
          If the pattern is not found, the function will return idaapi.BADADDR.
    """
    address = idc.find_binary(0, 1, pattern)
    if address != idaapi.BADADDR:
        function = idaapi.get_func(address)
    return address if address == idaapi.BADADDR else function.start_ea if function else idaapi.BADADDR

def find_offset_by_string(name: str, offset: int, op_value: int) -> int:
    """
    @brief Finds the offset of a given string in the binary and retrieves the operand value at a specified offset.

    @param name The name of the string to search for in the binary.
    @param offset The offset from the found address to calculate the target address.
    @param op_value The operand index from which to retrieve the value.

    @return The value of the operand at the calculated address if found; 
            otherwise, returns idaapi.BADADDR if the string or address is not found.
    """
    address = idc.find_binary(0, 1, f"\"{name}\"")
    if address == idaapi.BADADDR:
        return idaapi.BADADDR

    for xref in idautils.XrefsTo(address):
        dword = xref.frm + offset
        return idc.get_operand_value(dword, op_value) if dword != idaapi.BADADDR else idaapi.BADADDR

    return idaapi.BADADDR

def find_function_call(pattern: str) -> int:
    """
    @brief Searches for a binary pattern in the loaded binary and returns the value of the first operand.


    @param pattern A string representing the binary pattern to search for.

    @return The value of the first operand of the instruction containing the pattern if found; 
            otherwise, returns 0.
    """
    address = idc.find_binary(0, 1, pattern)
    return idc.get_operand_value(address, 0) if address != idaapi.BADADDR else 0

def get_function_name(address: int) -> Optional[str]:
    """
    @brief Retrieves the name of the function at a specified address.

    @param address The starting address of the function whose name is to be retrieved.

    @return A string containing the name of the function if it exists; 
            otherwise, returns None.

    @note This function uses the IDA Pro API to obtain the function object and then retrieves its name.
          If no function exists at the given address, the function will return None.
    """
    function = idaapi.get_func(address)
    return idc.get_name(function.start_ea) if function else None

def get_function_parameters(address: int) -> List[str]:
    """
    @brief Retrieves the names of the parameters for the function at a specified address.


    @param address The starting address of the function whose parameters are to be retrieved.

    @return A list of strings containing the names of the function parameters; 
            if the function has no parameters or does not exist, returns an empty list.
    """
    function = idaapi.get_func(address)
    if not function: return []

    paramc = idc.get_func_attr(function.start_ea, idc.FUNC_PARAM_COUNT)
    return [idc.get_struc_member_name(function.start_ea, i) for i in range(paramc) if idc.get_struc_member_name(function.start_ea, i)]

def get_function_return_type(address: int) -> str:
    """
    @brief Retrieves the return type of the function at a specified address.


    @param address The starting address of the function whose return type is to be retrieved.

    @return A string representing the return type of the function if it exists; 
            otherwise, returns an empty string.
    """
    function = idaapi.get_func(address)
    return idc.get_type(function.start_ea) if function else ""

def get_all_functions() -> List[Tuple[str, int]]:
    """
    @brief Retrieves a list of all functions in the current IDA database.

    @return A list of tuples, where each tuple contains the name of a function 
            and its starting address. The list may be empty if no functions are found.
    """
    return [(idc.get_name(function.start_ea), function.start_ea) for function in idaapi.get_functions()]

def search_function_by_name(name: str) -> int:
    """
    @brief Searches for a function by its name in the current IDA database.


    @param name The name of the function to search for.

    @return The starting address of the function if found; otherwise, returns idaapi.BADADDR.
    """
    for function in idaapi.get_functions():
        if name in idc.get_name(function.start_ea):
            return function.start_ea
    return idaapi.BADADDR

def get_function_size(address: int) -> int:
    """
    @brief Retrieves the size of a function given its starting address.


    @param address The starting address of the function.

    @return The size of the function in bytes; returns 0 if no function is found at the given address.
    """
    function = idaapi.get_func(address)
    return function.size() if function else 0

def get_function_instructions(address: int) -> List[str]:
    """
    @brief Retrieves the disassembly instructions of a function given its starting address.


    @param address The starting address of the function.

    @return A list of disassembly instructions for the function.
    """
    function = idaapi.get_func(address)
    return [idc.GetDisasm(head) for head in idautils.Heads(function.start_ea, function.end_ea)]

def rename_function(address: int, new_name: str) -> bool:
    """
    @brief Renames a function in the IDA database given its starting address.


    @param address The starting address of the function to rename.
    @param new_name The new name to assign to the function.

    @return True if the function was successfully renamed; otherwise, returns False.
    """
    function = idaapi.get_func(address)
    if function:
        idc.set_name(function.start_ea, new_name)
        return True
    return False

def get_function_callers(address: int) -> List[Tuple[str, int]]:
    """
    @brief Retrieves a list of functions that call the specified function.


    @param address The starting address of the function whose callers are to be found.

    @return A list of tuples, each containing the name and address of a caller function.
            If no callers are found, the list will be empty.
    """
    callers = list()
    for xref in idautils.XrefsTo(address):
        caller_address = xref.frm
        caller_function = idaapi.get_func(caller_address)
        if caller_function:
            caller_name = get_function_name(caller_function.start_ea)
            callers.append((caller_name, caller_address))
    return callers

def get_function_callees(address: int) -> List[Tuple[str, int]]:
    """
    @brief Retrieves a list of functions that are called by the specified function.


    @param address The starting address of the function whose callees are to be found.

    @return A list of tuples, each containing the name and address of a callee function.
            If no callees are found, the list will be empty.
    """
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
    """
    @brief Retrieves the comment associated with a function at the specified address.


    @param address The starting address of the function whose comment is to be retrieved.

    @return A string containing the function comment. If the function does not exist
            or has no comment, an empty string is returned.
    """
    function = idaapi.get_func(address)
    return idc.get_func_cmt(function.start_ea, 0) if function else ""

def set_function_comment(address: int, comment: str) -> bool:
    """
    @brief Sets a comment for the function at the specified address.


    @param address The starting address of the function for which the comment is to be set.
    @param comment The comment text to be associated with the function.

    @return True if the comment was successfully set, False if the function does not exist.
    """
    function = idaapi.get_func(address)
    if function:
        idc.set_func_cmt(function.start_ea, comment, 0)
        return True
    return False

def get_function_calling_convention(address: int) -> str:
    """
    @brief Retrieves the calling convention of the function at the specified address.


    @param address The starting address of the function whose calling convention is to be retrieved.

    @return A string representing the calling convention of the function. If the function does not exist,
            an empty string is returned.
    """
    function = idaapi.get_func(address)
    return idc.get_func_cc(function.start_ea) if function else ""

def get_function_local_variables(address: int) -> List[str]:
    """
    @brief Retrieves the names of local variables for the function at the specified address.


    @param address The starting address of the function whose local variables are to be retrieved.

    @return A list of strings containing the names of local variables. If the function does not exist
            or has no local variables, an empty list is returned.
    """
    function = idaapi.get_func(address)
    if not function: return []
    return [idc.get_struc_member_name(function.start_ea, i) for i in range(idc.get_func_attr(function.start_ea, idc.FUNC_LOCAL)) if idc.get_struc_member_name(function.start_ea, i)]

def get_function_stack_size(address: int) -> int:
    """
    @brief Retrieves the stack size of the function at the specified address.


    @param address The starting address of the function whose stack size is to be retrieved.

    @return The stack size of the function in bytes. If the function does not exist, 0 is returned.
    """
    function = idaapi.get_func(address)
    return idc.get_func_attr(function.start_ea, idc.FUNC_FRSIZE) if function else 0

def get_function_cyclomatic_complexity(address: int) -> int:
    """
    @brief Calculates the cyclomatic complexity of the function at the specified address.


    @param address The starting address of the function whose cyclomatic complexity is to be calculated.

    @return The cyclomatic complexity of the function. If the function does not exist, 0 is returned.
    """
    function = idaapi.get_func(address)
    if not function: return 0

    complexity = 1
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            insn = idautils.DecodeInstruction(head)
            if insn and insn.itype in [idaapi.NN_jmp, idaapi.NN_jmpf, idaapi.NN_call, idaapi.NN_callf]:
                    complexity += 1
    return complexity

def get_function_instruction_count(address: int) -> int:
    """
    @brief Counts the number of instructions in the function at the specified address.


    @param address The starting address of the function whose instruction count is to be calculated.

    @return The total number of instructions within the function. If the function does not exist,
            0 is returned.
    """
    function = idaapi.get_func(address)
    return sum(1 for _ in idautils.Heads(function.start_ea, function.end_ea)) if function else 0

def get_function_basic_blocks(address: int) -> List[Tuple[int, int]]:
    """
    @brief Retrieves the basic blocks of the function at the specified address.


    @param address The starting address of the function whose basic blocks are to be retrieved.

    @return A list of tuples, where each tuple contains the start and end addresses of a basic block
            within the function. If the function does not exist, an empty list is returned.
    """
    function = idaapi.get_func(address)
    blocks = list()

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
    """
    @brief Determines if there is a recursive call to the function at the specified address.


    @param address The address of the function to check for recursion.
    @param visited A set of addresses that have already been visited in the current recursion
                   to prevent infinite loops.

    @return True if the function at the specified address calls itself either directly or indirectly,
            False otherwise.
    """
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
    """
    @brief Retrieves memory accesses within the function at the specified address.


    @param address The starting address of the function whose memory accesses are to be retrieved.

    @return A list of strings representing the memory accesses within the function, including the
            instruction and its address. If the function does not exist or has no memory accesses,
            an empty list is returned.
    """
    function = idaapi.get_func(address)
    if not function:
        return []

    accesses = set()
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            insn = idautils.DecodeInstruction(head)
            if insn and insn.type in [idaapi.NN_mov, idaapi.NN_push, idaapi.NN_pop]:
                accesses.add(f"Instruction at {head}: {idc.GetDisasm(head)}")

    return list(accesses)

def get_function_mem_usage(address: int) -> int:
    """
    @brief Calculates the memory usage of the function at the specified address.


    @param address The address of the function for which to calculate memory usage.

    @return The total memory usage of the function, including its size and stack size. 
            Returns 0 if the function does not exist.
    """
    function = idaapi.get_func(address)
    if function is None: return 0

    total_usage = function.size()
    total_usage += get_function_stack_size(address)

    return total_usage

def compare_functions(address1: int, address2: int) -> float:
    """
    @brief Compares the similarity between two functions at the specified addresses.


    @param address1 The address of the first function to compare.
    @param address2 The address of the second function to compare.

    @return A ratio representing the similarity between the two functions, ranging from 0 (completely dissimilar) to 1 (identical).
    """
    return __import__("difflib").SequenceMatcher(None, get_function_instructions(address1), get_function_instructions(address2)).ratio()

def visualize_function_control_flow_graph(address: int) -> None:
    """
    @brief Visualizes the control flow graph of the function at the specified address.


    @param address The address of the function to visualize.

    @note The visualization is displayed using matplotlib.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

    graph = nx.DiGraph()
    for instruction in get_function_instructions(address):
        graph.add_node(instruction, idc.GetDisasm(instruction))
        for xref in idautils.XrefsFrom(instruction):
            graph.add_edge(instruction, xref.to)

    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightred", font_size=10, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, 'weight'))
    plt.title("Function Control Flow Graph")
    plt.show()

def visualize_function_call_graph(address: int) -> None:
    """
    @brief Visualizes the call graph of the function at the specified address.


    @param address The address of the function to visualize.

    @note The visualization is displayed using matplotlib.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

    graph = nx.DiGraph()
    for callee_name, _ in get_function_callees(address):
        graph.add_edge(get_function_name(address), callee_name)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold")
    plt.title("Function Call Graph")
    plt.show()

def analyze_function_call_frequency(address: int) -> dict:
    """
    @brief Analyzes the call frequency of a function at the specified address.


    @param address The address of the function to analyze.

    @return A dictionary where keys are addresses of functions called by the callee,
            and values are the frequency of calls to those functions.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

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
    """
    @brief Visualizes the call patterns of the function at the specified address.


    @param address The address of the function whose call patterns are to be visualized.

    @note This function generates a directed graph using NetworkX and displays it with Matplotlib.
          If the function at the specified address does not exist, a message will be printed.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

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
    """
    @brief Visualizes the dependencies of the function at the specified address.

    @param address The address of the function whose dependencies are to be visualized.

    @note This function creates a directed graph to represent the relationships
          between the function and its callees. The graph is displayed. If the
          function at the specified address does not exist, a message will be 
          printed to the console.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

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
    """
    @brief Generates a heatmap visualizing the similarity between functions.


    @param threshold A float representing the similarity score threshold. 
                     Only similarity scores above this threshold will be displayed 
                     in the heatmap. Scores below this threshold will be represented 
                     as zero in the matrix.

    @note If no functions are found, a message will be printed to indicate that 
          no functions were detected.
    """
    functions = get_all_functions()
    if not functions:
        print("Didn't find any functions at all.")
        return

    num_functions = len(functions)
    sim_matrix = np.zeros((num_functions, num_functions))

    for i, (_, address1) in enumerate(functions):
        for j, (_, address2) in enumerate(functions):
            if i != j:
                similarity = compare_functions(address1, address2)
                sim_matrix[i, j] = similarity if similarity > threshold else 0

    # Create a heatmap
    plt.figure(figsize=(10, 8))
    sb.heatmap(sim_matrix, 
                xticklabels=[name for name, _ in functions], 
                yticklabels=[name for name, _ in functions],
                cmap='coolwarm', 
                cbar_kws={'label': 'Similarity Score'})
    plt.title("Function Similarity Heatmap")
    plt.xlabel("Functions")
    plt.ylabel("Functions")
    plt.show()

def visualize_function_complexity(address: int) -> None:
    """
    @brief Visualizes the cyclomatic complexity of a function at a given address.


    @param address An integer representing the address of the function to be analyzed.

    @note If the function at the specified address does not exist, a message will 
          be printed to indicate that the function could not be found.
    """
    function = idaapi.get_func(address)
    if not function:
        print(f"Function at address {address} does not exist.")
        return

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

def cluster_similar_functions(threshold: float) -> list:
    """
    @brief Clusters functions based on their similarity.


    @param threshold A float representing the minimum similarity score required 
                     for two functions to be considered part of the same cluster. 
                     A higher threshold means stricter similarity criteria.

    @return A list of clusters, where each cluster is a list of addresses of 
            similar functions. Each cluster contains function addresses that have 
            a similarity score above the specified threshold.
    
    @note The function uses the `compare_functions` method to determine the 
          similarity between functions.
    """
    functions = get_all_functions()
    clusters = list()

    for i, (_, address1) in enumerate(functions):
        cluster = [address1]
        for j, (_, address2) in enumerate(functions):
            if i != j and compare_functions(address1, address2) > threshold:
                cluster.append(address2)
        clusters.append(cluster)
    return clusters

def recognize_instruction_patterns(address: int) -> dict:
    """
    @brief Recognizes instruction patterns within a function.


    @param address An integer representing the address of the function to analyze.

    @return A dictionary where the keys are strings representing the instruction 
            patterns (formatted as 'instruction_type:operand1_type:operand2_type') 
            and the values are integers representing the count of how many times 
            each pattern occurs within the function.

    @note If the function at the specified address does not exist, an empty 
          dictionary will be returned.
    """
    function = idaapi.get_func(address)
    patterns = dict()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            insn = idautils.DecodeInstruction(head)
            if insn:
                pattern = f"{insn.itype}:{insn.Op1.type}:{insn.Op2.type}"
                patterns[pattern] = patterns.get(pattern, 0) + 1
        return patterns

def analyze_function_call_frequency(address: int) -> dict:
    """
    @brief Analyzes the frequency of function calls for a given function.


    @param address An integer representing the address of the function to analyze.

    @return A dictionary with the function's starting address as the key and the 
            number of callees as the value.

    @note If the function at the specified address does not exist, an empty 
          dictionary will be returned.
    """
    function = idaapi.get_func(address)
    if function is None: return {}

    callees = get_function_callees(function.start_ea)
    return {function.start_ea: len(callees)}

def get_function_referenced_variables(address: int) -> List[str]:
    """
    @brief Retrieves the names of variables referenced within a function.


    @param address An integer representing the address of the function to analyze.

    @return A list of strings containing the names of variables referenced 
            within the function. If the function does not exist or has no 
            referenced variables, an empty list is returned.

    @note The function uses IDA Pro's API to access function and operand information.
    """
    function = idaapi.get_func(address)
    if not function: return []

    ref_vars = set()
    for head in idautils.Heads(function.start_ea, function.end_ea):
        if idc.is_code(idc.getFlags(head)):
            for op in range(idc.get_opnd_count(head)):
                operand = idc.get_operand_value(head, op)
                var_name = idc.get_name(operand)
                if var_name:
                    ref_vars.add(var_name)
    return list(ref_vars)

def find_unused_functions() -> List[str]:
    """
    @brief Identifies functions that are not called by any other functions.


    @return A list of strings containing the names of functions that are not 
            called by any other functions. If all functions are used, an empty 
            list is returned.

    @note This function relies on the availability of a function to retrieve 
          all functions and their callees.
    """
    functions = get_all_functions()
    used_functions = set()

    for _, address in functions:
        callees = get_function_callees(address)
        used_functions.update(callee_name for callee_name, _ in callees)

    return [name for name, _ in functions if name not in used_functions]

def detect_function_anomalies(threshold: int = 5) -> List[str]:
    """
    @brief Detects anomalies in functions based on complexity and size.


    @param threshold An integer representing the threshold for complexity and size. 
                     The default value is 5.

    @return A list of strings containing the names of functions that exhibit 
            anomalies based on the defined thresholds. If no anomalies are found, 
            an empty list is returned.

    @note The size threshold is calculated as 100 times the complexity threshold.
    """
    functions = get_all_functions()
    anomalies = []

    for name, address in functions:
        complexity = get_function_cyclomatic_complexity(address)
        size = get_function_size(address)
        if complexity > threshold or size > threshold * 100:
            anomalies.append(name)

    return anomalies

def get_function_call_depth(address: int) -> int:
    """
    @brief Calculates the maximum call depth of a function.


    @param address The address of the function to analyze.

    @return An integer representing the maximum call depth of the function. 
            If the function does not exist or has no callees, returns 1.

    @note The function uses a recursive approach to traverse the call graph.
    """
    def helper(addr: int, depth: int) -> int:
        """
        @brief A recursive helper function to calculate call depth.


        @param addr The address of the function to analyze.
        @param depth An integer representing the current depth in the call graph.

        @return An integer representing the maximum call depth from the current address.
        """
        callees = get_function_callees(addr)
        if not callees:
            return depth
        return max(helper(callee_address, depth + 1) for _, callee_address in callees)
    return helper(address, 1)

def get_function_str_literals(address: int) -> List[str]:
    """
    @brief Retrieves string literals from a function.

    This function analyzes the specified function at the given address and 
    returns a list of string literals that are referenced within its code.

    @param address An integer representing the address of the function to analyze.

    @return A list of string literals found within the function's code. 
            If the function does not exist or has no string literals, an empty list is returned.

    @note This function relies on the underlying analysis to identify string literals.
    """
    function = idaapi.get_func(address)
    str_literals = set()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            for op in range(idc.get_opnd_count(head)):
                operand = idc.get_operand_value(head, op)
                if idc.get_type(operand) == "string":
                    str_literals.add(idc.get_strlit_contents(operand))
    return list(str_literals)

def get_function_inlining_candidates(threshold: int) -> List[Tuple[str, int]]:
    """
    @brief Retrieves a list of functions that are suitable for inlining.


    @param threshold An integer representing the maximum size of a function 
                     that can be inlined.

    @return A list of tuples where each tuple contains the name and address of a 
            function that is smaller than the specified threshold.

    @note This function relies on the underlying analysis to determine function sizes.
    """
    candidates = set()
    for name, address in get_all_functions():
        size = get_function_size(address)
        if size < threshold:
            candidates.add((name, address))
    return list(candidates)

def analyze_function_branching(address: int) -> Dict[str, int]:
    """
    @brief Analyzes the branching behavior of a function.

    This function analyzes the specified function at the given address and 
    returns a dictionary containing statistics about its branching behavior.

    @param address An integer representing the address of the function to analyze.

    @return A dictionary containing the following keys:
            - total_branches: The total number of branches in the function.
            - conditional_branches: The number of conditional branches in the function.
            - unconditional_branches: The number of unconditional branches in the function.

    @note This function relies on the underlying analysis to identify branches.
    """
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
    """
    @brief Identifies hotspots within a function based on instruction frequency.


    @param address An integer representing the address of the function to analyze.
    @param threshold An integer representing the minimum execution count for an 
                     instruction to be considered a hotspot (default is 5).

    @return A list of tuples, where each tuple contains the address of the hotspot 
            and its disassembly string. If no hotspots are found, an empty list is returned.

    @note This function relies on the underlying analysis to count instruction executions.
    """
    function = idaapi.get_func(address)
    hotspots = dict()

    if function:
        for head in idautils.Heads(function.start_ea, function.end_ea):
            if idc.is_code(idc.getFlags(head)):
                if idautils.DecodeInstruction(head):
                    hotspots[head] = hotspots.get(head, 0) + 1
    return [(addr, idc.GetDisasm(addr)) for addr, count in hotspots.items() if count >= threshold]

def detect_dead_code() -> List[Tuple[str, int]]:
    """
    @brief Detects dead code in the program.


    @return A list of tuples where each tuple contains the name and address of 
            a function that is not called by any other function.

    @note This function collects all called functions and compares them against 
          the list of all functions to identify dead code.
    """
    functions = get_all_functions()
    called = set()

    for _, address in functions:
        for callee_name, _ in get_function_callees(address):
            called.add(callee_name)
    return [(name, address) for name, address in functions if name not in called]
# ; <=====================================>
# ; FUNCTION SECTION END
# ; <=====================================>

# <<<<<<<<<<<<<<<<<<<EOF>>>>>>>>>>>>>>>>>>>