```
    _________     
   / __/__  /_____
  / /_  /_ </ ___/
 / __/___/ (__  ) 
/_/  /____/____/  
```

# f3s <!-- omit in toc -->
> Format String Static Scanner is a static analysis tool for format string vulnerabilities in binaries.

- [1. About](#1-about)
  - [1.1. What does f3s do?](#11-what-does-f3s-do)
  - [Example usage](#example-usage)
  - [2.1. What binary architectures are supported?](#21-what-binary-architectures-are-supported)
  - [2.2. What function sinks f3s looks for?](#22-what-function-sinks-f3s-looks-for)
  - [2.3. What is a static taint analysis and how does it work?](#23-what-is-a-static-taint-analysis-and-how-does-it-work)
  - [2.4. What static analyses and static binary techniques f3s makes use of?](#24-what-static-analyses-and-static-binary-techniques-f3s-makes-use-of)
  - [2.5. What is a format string vulnerability?](#25-what-is-a-format-string-vulnerability)
- [3. Dependencies and installation](#3-dependencies-and-installation)
- [4. Tests](#4-tests)
- [5. Roadmap](#5-roadmap)
- [6. Contributing](#6-contributing)
- [7. Acknowledgments](#7-acknowledgments)
- [8. Meta](#8-meta)


# 1. About
## 1.1. What does f3s do?
f3s makes use of a combination of static analyses directly on raw binaries to spot format string vulnerabilities. 

A function (called sink) is flagged if the corresponding format parameter is found to be coming from user input. 

For every flag it does also display a callstack trace of the path that brought from the starting top function to the vulnerability found. 

f3s works on different types of architectures and stripped binaries.

<p align="center">
  <img src="https://i.ibb.co/5TRZCS5/meme.png" alt="Your Image Alt Text" width=500>
</p>

## Example usage
<p align="center">
  <img src="https://i.ibb.co/ZzvvBsD/PHOTO-2024-07-11-20-17-42.jpg" alt="Your Image Alt Text" width=500>
</p>
<p align="center">
  <i>Use `-h` option to discover all other arguments.</i>
</p>


## 2.1. What binary architectures are supported?
Currently f3s has been tested and works over these architectures:
 - AMD64
 - ARM32
 - ARM64

## 2.2. What function sinks f3s looks for?
You can find and extend the checked functions with their respective parameters at `./src/sinks/fs_sinks.py`. 
Here is the list of the currently ones present in the file
 - printf
 - fprintf
 - sprintf
 - dprintf
 - snprintf 
 - vprintf
 - vfprintf 
 - vdprintf 
 - vsprintf 
 - vsnprintf
 - syslog

## 2.3. What is a static taint analysis and how does it work?
*Static* means it does not make use of running the binary to build knowledge out of it but rather just look at the machine code. There are few important concepts you should know about taint analysis:
 - Taint: a taint is a flag that is logically associated with a particular datum. Tainted sources are usually user input arguments to a binary.
 - Elaboration of tainted data: everything that touches taint gets tainted. So every output of every function that takes in tainted data will be tainted. This is tipically for keeping track of where the user input has flowed.
 - Sink: a sink is a parameter of a possible vulnerable function. Usually function+parameter matches are pre-known and checked during the analysis
 - Sink + Taint: when we find a sink that takes in a tainted value we know that our possible malicious data reached a possible vulnerable function and we trigger a report.

## 2.4. What static analyses and static binary techniques f3s makes use of?
 - VEX intermediate representation included in angr to lift-up the binaries and operate with architecture agnostic code.
 - Taint analysis for tainting input and reporting of sinks.
 - Calling Convetion Analysis is made to asses the architecture of the binary and its calling convention.
 - A Control Flow Graph Analysis is carried out to asses the presence of sinks and derive a set of callstack traces to it.
 - A modified recursive Reaching Definition Analysis is laid out for every trace starting from the first top function and going forward towards the sink.
 - A that point the Calling Convention, tainting of input and vulnerable sinks parameters are combined to asses if they will contain a tainted value.

## 2.5. What is a format string vulnerability?
```
printf("wow!")             //wow!!
printf("%s", "wow!")       //wow!
printf("%s %x", "wow!")    //wow! 0x4567B4AC    <-- stack content, information leakage!
printf("%s %2$x", "wow!")  //wow! 0x21776F77    <-- "wow!" string in stack after a offset of 2
printf("%s %2$n", "wow!")  //segmentation fault <-- selective memory corruption
```
When the format string "%x %x" is parsed the function expects two parameters, depending on the calling convention, in the stack. When these parameters are not supplied by the caller what was previously in the stack gets read. A special formatter `%n` could be used to write. If the user has control over the format string (e.g.: its supplied directly from input) it could craft it in such a wat to selectively leak and write arbitrarly information into the stack. This is a [wikipedia article](https://en.wikipedia.org/wiki/Uncontrolled_format_string) talking about format string vulnerability.

# 3. Dependencies and installation
In the file `./requirements.txt` you can find a list of dependencies f3s relies on. You can install through pip with the command: `pip install -r requirements.txt`.

# 4. Tests
Under `./tests` you can find a collection of ad-hoc made source codes to test and demonstrate the capabilities of f3s. To run all the tests do `pytest run_tests.py`.
> ⚠️ NOTE you should have gcc and both a ARM64 and ARM32 cross compiler installed in your systems to run the tests.

# 5. Roadmap
- [X] Create f3s first version.
- [ ] Create a Docker image containing the toolbox and all the dependent software already setup
- [ ] Extend f3s also for command injection vulnerabilities

See the [open issues](https://github.com/thisisnotgcsar/f3s/issues) for a full list of proposed features (and known issues).

# 6. Contributing
Contributions are more than welcome! Here's a [short video tutorial](https://www.youtube.com/watch?v=8lGpZkjnkt4) on how to open a pull request.

# 7. Acknowledgments
 - [operation-mango](https://github.com/sefcom/operation-mango-public/tree/master) in particular for the argument_resolver module
 - [pamplemousse](https://blog.xaviermaso.com/) in particular for its [lecture video](https://youtu.be/4SMRnpuqN6E?si=a8w28haScE-jnfZN) and [blog post](https://blog.xaviermaso.com/2021/02/25/Handle-function-calls-during-static-analysis-with-angr.html)
 - [angr](https://github.com/angr/angr)

# 8. Meta
gcsar

 <p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><a property="dct:title" rel="cc:attributionURL" href="https://github.com/thisisnotgcsar/f3s">f3s</a> by <a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://github.com/thisisnotgcsar">gcsar</a> is licensed under <a href="https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1" target="_blank" rel="license noopener noreferrer" style="display:inline-block;">CC BY-NC-SA 4.0<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/nc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1" alt=""></a></p>

https://github.com/thisisnotgcsar
