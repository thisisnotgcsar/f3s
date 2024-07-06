from sinks.sink import Sink

# GIULIO GOLINELLI
# golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
#
# File containing different sinks typical for format string vulnerabilities

printf = Sink("printf", [1])
fprintf = Sink("fprintf", [2])
sprintf = Sink("sprintf", [2])
dprintf = Sink("dprintf", [2])
snprintf = Sink("snprintf", [3])
vprintf = Sink("vprintf", [1])
vfprintf = Sink("vfprintf", [2])
vdprintf = Sink("vdprintf", [2])
vsprintf = Sink("vsprintf", [2])
vsnprintf = Sink("vsnprintf", [3])
syslog = Sink("syslog", [2])

FORMAT_STRING_SINKS: dict[str, Sink] = {
	"printf": printf,
	"fprintf": fprintf,
	"sprintf": sprintf,
	"dprintf": dprintf,
	"snprintf": snprintf,
	"vprintf": vprintf,
	"vfprintf": vfprintf, 
	"vdprintf": vdprintf,
	"vsprintf": vsprintf,
	"vsnprintf": vsnprintf,
	"syslog": syslog
}
"""
A dictionary of already definied Sinks for format string vulenrability.
"""