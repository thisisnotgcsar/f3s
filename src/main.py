from angr import Project
from angr.analyses.analysis import AnalysisFactory
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from argument_resolver.utils.rda import CustomRDA
from argument_resolver.handlers import handler_factory, StdioHandlers
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.call_trace import traces_to_sink
from argument_resolver.utils.call_trace_visitor import CallTraceSubject
from argument_resolver.external_function.sink.sink_lists import STRING_FORMAT_SINKS


def subject_from_function(project, function, depth=1):
	traces = traces_to_sink(function, project.kb.functions.callgraph, depth, [])
	assert len(traces) == 1
	trace = traces.pop()
	function_address = trace.current_function_address()
	init_function = project.kb.functions[function_address]
	return CallTraceSubject(trace, init_function)

project = Project("tests/a.out", auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True)
project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)

RDA = AnalysisFactory(project, CustomRDA)
handler = handler_factory([StdioHandlers])(project, False)
sprintf = project.kb.functions.function(name="sprintf")
assert(sprintf != None)
observation_points = set(Utils.get_all_callsites(project))
subject = subject_from_function(project, sprintf)

rda = RDA(
	subject=subject,
	observation_points=observation_points,
	function_handler=handler,
	dep_graph=DepGraph(),
)

# take the resulting state of the RDA for the sink function
# contains its live definitions and their symbolic addresses
results = handler.analyzed_list[-1].state

# Deduce possible prototype of the function thanks to calling convention analysis
# atoms not alive after the call of the function AND
# atoms not defined at the begging of the function after call
# Connects the possible argument to the runtime machine memory locations as Symbolic References
cc = project.analyses.CallingConvention(sprintf).cc

# Iterates through all possible arg positions that can contain an integer or a pointer
# and it associates them a SimRegArg or SimStackArg
number = list(filter(lambda x: x.name == "sprintf", STRING_FORMAT_SINKS))[0].vulnerable_parameters[0]
args = cc.int_args

for i in range(number):
	next(args)
arg_dst = next(args)

# returns the symbolic address of the argument produced by RDA based on the SimRegArg|SimStackArg passed
dst_values = Utils.get_values_from_cc_arg(arg_dst, results, rda.project.arch)

# Tries to resolve the Symbolic address into a value
value = Utils.get_strings_from_pointers(dst_values, results, None)

# tells if value comes from input
assert(results.is_top(value.one_value()) == True)