from angr import Project
import os

EXECUTABLE_PATH = "./tests/a.exe"

# Creating angr project
project = Project(EXECUTABLE_PATH, load_options={'auto_load_libs': False})

# Building the CFG
cfg = project.analyses.CFGFast()

# printing architecture discovered
print(project.arch)

# getting main function
main_function = project.kb.functions.function(name="main")
print(main_function)

# get the first block of the main function
main_block_0_1 = list(main_function.blocks)[0]
print(main_block_0_1)

# still getting the main first block but via another path
main_block_0_2 = cfg.model.get_any_node(main_function.addr)
print(main_block_0_2)
