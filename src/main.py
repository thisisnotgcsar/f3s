import angr

EXECUTABLE_PATH = "../TESTS/straight/straight.exe"

# Creating angr project
proj = angr.Project(EXECUTABLE_PATH, load_options={'auto_load_libs': False})

# Creatin CFG of executable
cfg = proj.analyses.CFGEmulated(keep_state=True)

# This grabs any node at a given location
entry_node = cfg.get_any_node(proj.entry)

entry_node = entry_node.successors[0].successors[0]
print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])
