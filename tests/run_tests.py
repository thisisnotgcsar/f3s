import subprocess
import os
from enum import Enum

class Compiler(Enum):
	GCC = "gcc"
	ARM64 = "aarch64-linux-gnu-gcc"
	ARM32 = "arm-linux-gnueabihf-gcc"

# setup function run by all the tests to compile the c source
# for analyzing the respective binary of the current test
def _compile(source_file: str, compiler: Compiler = Compiler.GCC) -> None:
	os.chdir(os.path.dirname(__file__))				# change working directory to tests directory
	compile_command = [compiler.value, "-O0", "-fno-builtin", source_file]
	subprocess.run(compile_command, check=True)
	os.chdir(os.path.join(os.path.dirname(__file__), '..'))		# going back to root

f3s_command = ["python3", "f3s.py", "./tests/a.out"]

def launch_f3s(command: list[str] = f3s_command) -> subprocess.CompletedProcess:
	return subprocess.run(command, capture_output=True, check=True) # check ensures subprocess returned 0
																	# in this case meaning it found vulnerabilities

def test_simple_printf() -> None:
	_compile("./simple_printf.c")
	launch_f3s()

def test_simple_sprintf() -> None:
	_compile("./simple_sprintf.c")
	launch_f3s()

def test_check() -> None:
	_compile("./check.c")
	launch_f3s()

def test_multiple_traces() -> None:
	_compile("./multiple_traces.c")
	# there are 2 different traces leading to sink
	output: str = launch_f3s().stdout.decode("utf-8")
	output: list[str] = output.splitlines()
	# checking last 2 lines (dodge banner logo)
	assert output[-1].startswith('printf') and output[-2].startswith('printf')	# 2 reports

def test_hided() -> None:
	_compile("./hided.c")
	launch_f3s()

def test_false_alarm() -> None:
	_compile("./false_alarm.c")
	# if no vulnerable sinks found, exit code is 1
	assert subprocess.run(f3s_command, capture_output=True).returncode == 1

def test_depth() -> None:
	_compile("./depth.c")
	# in this case e want to test for a deep call trace
	# call trace is separated with spaces
	output: str = launch_f3s(f3s_command + ["-d", "99"]).stdout.decode("utf-8")
	lastline = output.splitlines()[-1]
	assert lastline.count(' ') == 6		# checking for a deep calltrace

def test_simple_printf_ARM64() -> None:
	_compile("./simple_printf.c", Compiler.ARM64)
	launch_f3s()

def test_simple_printf_ARM32() -> None:
	_compile("./simple_printf.c", Compiler.ARM32)
	launch_f3s()