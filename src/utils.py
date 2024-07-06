
banner = """
	_________     
   / __/__  /_____
  / /_  /_ </ ___/
 / __/___/ (__  ) 
/_/  /____/____/  
GIULIO GOLINELLI - golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
**********************************************
"""

log_enable: bool = False
"""
weather enabling or not the log output.
"""

class colors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKCYAN = '\033[96m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	SYSTEM = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

def red(message: str = "") -> str:
	"""
	just prints in red the message given
	## parameters
		- message (str): the message to write in red.
	"""
	return colors.RED + message + colors.SYSTEM

def green(message: str = "") -> str:
	"""
	just prints in green the message given
	## parameters
		- message (str): the message to write in green.
	"""
	return colors.GREEN + message + colors.SYSTEM

def yellow(message: str = "") -> str:
	"""
	just prints in yellow the message given
	## parameters
		- message (str): the message to write in yellow.
	"""
	return colors.YELLOW + message + colors.SYSTEM

def log(*args) -> None:
	"""
	Adds a prefix to the message before printing it to stdout.
	## parameters
		- args: the other parameters to pass to the print function.
	"""
	if log_enable == True:
		print(f"[{red('f3s')}]:", *args)

def print_banner() -> None:
	"""
	Prints the banner to stdout.
	"""
	print(banner)
	
