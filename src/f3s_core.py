from angr import Project
from angr.knowledge_plugins.functions.function import Function
from angr.analyses.analysis import AnalysisFactory
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.calling_conventions import SimFunctionArgument
from angr.analyses.reaching_definitions.call_trace import CallTrace, CallSite
from argument_resolver.utils.rda import CustomRDA
from argument_resolver.handlers import handler_factory, StdioHandlers
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.call_trace import traces_to_sink
from argument_resolver.utils.call_trace_visitor import CallTraceSubject
from sinks.fs_sinks import FORMAT_STRING_SINKS
from typing import Callable
import sys
import utils

# GIULIO GOLINELLI
# golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
#
# This is the main code that unifies argument_resolver and angr
# To make format string static scanning

__all__ = ['f3s']

# Given a function in input (usually a sink) explores all calltraces that bring to the sink
# And the creates a subject for the RDA with the trace and the given sink
# depth is the how much deep to traverse backward the CFG to get to know the complete calltrace
# TODO there is a bug here with depth > 2 and sinks that are directly in main
# check gen_traces_to_sink maybe for the bug. Anyway i think the bug is in the trace parameter of CallTraceSubject
# Possibel solution se la traccia è uguale a 3 e la prima funzione è _start, cut it
def _subjects_from_function(project: Project, function: Function, depth: int) -> list[CallTraceSubject]:
	traces = list(traces_to_sink(function, project.kb.functions.callgraph, depth, []))	# Backward Slices to the sink
	return list(map(lambda trace: CallTraceSubject(
					trace, 
					project.kb.functions[trace.callsites[0].caller_func_addr]),	# taking the address of the caller function
																				# that calls the sink
																				# its in last (first) callsite
																				# and that will be the subject for RDA												
				traces))

# link the vulnerable argument positions from the FORMAT_STRING_SINKS of the function
# to the symbolic atoms taken from the calling convention
def _get_sim_atoms_from_sink(f: Function) -> list[SimFunctionArgument]:
	sym_atoms: list[SimFunctionArgument] = list(f.calling_convention.int_args)
	vuln_reg_names: list[str] = [f.calling_convention.ARG_REGS[i] \
							  for i in FORMAT_STRING_SINKS[f.name].parameter_positions]
	vuln_sym_atoms: list[SimFunctionArgument] = [x for x in sym_atoms if x.reg_name in vuln_reg_names]
	return vuln_sym_atoms

# returns a list representing the calltrace with
# all its callsites in the format {function name} (str) {address} (int) -> next
def _flat_calltrace(project: Project, calltrace: CallTrace) -> list[tuple[str, int]]:
	# given a function address returns a tuple containing function name, function address
	addr_name_addr: Callable[[int], tuple[str, int]] = lambda addr: (project.kb.functions[addr].name, addr)
	callsites: list[CallSite] = list(reversed(calltrace.callsites))			# reverse order from root of CFG to sink
	result = list(map(lambda callsite: addr_name_addr(callsite.caller_func_addr), callsites))	# process the callers
	return result

def f3s(binary_path: str, depth: int, verbose: bool = False) -> list[tuple[str, int, list[tuple[str, int]]]]:
	"""
	Main function to be called for format string vulnerability discovery.

	## Arguments
		- binary_path (str): the path of the binary to analyze
		- verbose (bool): if should output verbose information

	## Return
		A list of tuples for each vulnerable function found, containg:
		
		- name (str)
		- address (int)
		- calltrace (list[tuple[str, int]]): found trace bringing to sink in format [name] (address) -> next for each function
	"""

	# enables log of verbose messages
	utils.log_enable = verbose

	# initialize return list
	results: list[tuple[str, int, list[tuple[str, int]]]] = []

	# Doing standard angr analyses on the provided binary
	project = Project(binary_path, auto_load_libs=False)
	cfg = project.analyses.CFGFast(normalize=True, data_references=True)

	# 	- atoms not alive after the call of the function AND
	# 	- atoms not defined at the begging of the function after call
	project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)

	# Intantiating the modified RDA and handler
	# the handler does the business logic as it was the function under analysis
	# and should be implemented properly for every possible interesting function
	RDA = AnalysisFactory(project, CustomRDA)
	handler = handler_factory([StdioHandlers])(project, False)

	# observation points BEFORE and AFTER placed at every call of funtion
	# either external or internal
	observation_points = set(Utils.get_all_callsites(project))

	# take all function found in the binary and interesect them
	# with all the theoretical sinks
	f_sinks_found: set[Function] = {y for y in \
			{project.kb.functions.function(name=x) for x in FORMAT_STRING_SINKS.keys()} \
		if y != None}
	utils.log(f"Found {len(f_sinks_found)} possible sinks:", *[f.name for f in f_sinks_found])

	for f in f_sinks_found:		# For every possible format string sink found
		vuln_sym_atoms = _get_sim_atoms_from_sink(f)	# get the vulnerable atoms of function parameters
		utils.log(f"Now analyzing {utils.green(f.name)} ({hex(f.addr)})")
		subjects = _subjects_from_function(project, f, depth)			# Every calltrace that brings to the sink
		utils.log(f"found {len(subjects)} calltraces to sink")

		for i, s in enumerate(subjects):		# will be a subject of the analysis
			utils.log(f"starting RDA for sink {utils.green(f.name)} and calltrace {i}")

			# starts modified Reaching Definition Analysis
			# taiting + recursive
			rda = RDA(
				subject=s,
				observation_points=observation_points,
				function_handler=handler,
				dep_graph=DepGraph()
			)

			# take the resulting state of the RDA for the sink function
			# contains its live definitions and their symbolic addresses
			rda_results = handler.analyzed_list[-1].state

			for a in vuln_sym_atoms:	# for every vulnerable sym atoms of function parameters
				utils.log(f"Reconstructing symbolic value from vulnerable atom {a}")
				
				# Computes the set of symbolic addresses of the symbolic atom
				# corresponding to the values of the symbolc atom
				# Defined if static or Symbolic addresses if dynamic
				dst_values = Utils.get_values_from_cc_arg(a, rda_results, rda.project.arch)
				
				# Reads every symbolic address and translate it into a Symbolic values
				# Remains a symbolic address if dynamic
				value = Utils.get_strings_from_pointers(dst_values, rda_results, None)

				# tells if value comes from stdin!
				# it does this by checking if the value was tainted
				if rda_results.is_top(value.one_value()) == True:
					utils.log(utils.yellow(f"ATOM {a} of {f.name} @ {hex(f.addr)} FOUND VULNERABLE!"))
					results.append((f.name, f.addr, _flat_calltrace(project, s.content)))

	return results


if __name__ == "__main__":
	sys.stderr.write("This is a module should not be run.\n")
	exit(0)