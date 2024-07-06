# GIULIO GOLINELLI
# golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
#
# Sink definition

class Sink:
	"""
	Represents a Sink. In taint analysis, a Sink is a function from where a vulnerability could happen.
	##Properties:
		- name (str): the name of the function
		- parameter_positions (list[int]): positions of the possible vulnerable parameters of the function.
	"""
	name: str
	"""
	Name of the function.
	"""
	parameter_positions: list[int]
	"""
	Position of the vulnerable parameters starting from 0.
	They have to be associated with the specific architecture calling convention.
	"""

	def __init__(self, name: str, parameter_positions: list[int]) -> None:
		self.name = name
		self.parameter_positions = parameter_positions