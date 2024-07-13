from sinks.sink import Sink

# GIULIO GOLINELLI
# golinelli.giulio13@gmail.com - https://github.com/thisisnotgcsar
#
# File containing different sinks typical for format string vulnerabilities

printf = Sink("printf", [0])
fprintf = Sink("fprintf", [1])
sprintf = Sink("sprintf", [1])
dprintf = Sink("dprintf", [1])
snprintf = Sink("snprintf", [2])
vprintf = Sink("vprintf", [0])
vfprintf = Sink("vfprintf", [1])
vdprintf = Sink("vdprintf", [1])
vsprintf = Sink("vsprintf", [1])
vsnprintf = Sink("vsnprintf", [2])
syslog = Sink("syslog", [1])

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