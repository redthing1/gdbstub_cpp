# Debugging with GDB - Protocol

Go to the [first](gdb_1.html), [previous](gdb_128.html), [next](gdb_130.html), [last](gdb_268.html) section, [table of contents](gdb_toc.html).

---

#### [Communication protocol](about:blank/gdb_toc.html#TOC134)

The stub files provided with GDB implement the target side of the communication
protocol, and the GDB side is implemented in the GDB source file `remote.c'.
Normally, you can simply allow these subroutines to communicate, and ignore the
details. (If you're implementing your own stub file, you can still ignore the
details: start with one of the existing stub files. `sparc-stub.c' is the best
organized, and therefore the easiest to read.)

However, there may be occasions when you need to know something about the
protocol--for example, if there is only one serial port to your target machine,
you might want your program to do something special if it recognizes a packet
meant for GDB.

In the examples below, ``<-'` and ``->'` are used to indicate transmitted and
received data respectfully.

All GDB commands and responses (other than acknowledgments) are sent as a
packet. A packet is introduced with the character ``$'`, the actual packet-data,
and the terminating character ``#'` followed by a two-digit checksum:

```
$packet-data#checksum

```

The two-digit checksum is computed as the modulo 256 sum of all characters
between the leading ``$'` and the trailing ``#'` (an eight bit unsigned
checksum).

Implementors should note that prior to GDB 5.0 the protocol specification also
included an optional two-digit sequence-id:

```
$sequence-id:packet-data#checksum

```

That sequence-id was appended to the acknowledgment. GDB has never output
sequence-ids. Stubs that handle packets added since GDB 5.0 must not accept
sequence-id.

When either the host or the target machine receives a packet, the first response
expected is an acknowledgment: either ``+'` (to indicate the package was
received correctly) or ``-'` (to request retransmission):

```
<- $packet-data#checksum
-> +

```

The host (GDB) sends commands, and the target (the debugging stub incorporated
in your program) sends a response. In the case of step and continue commands,
the response is only sent when the operation has completed (the target has again
stopped).

packet-data consists of a sequence of characters with the exception of ``#'` and
``$'` (see ``X'` packet for additional exceptions).

Fields within the packet should be separated using ``,'` ``;'` or ``:'`. Except
where otherwise noted all numbers are represented in HEX with leading zeros
suppressed.

Implementors should note that prior to GDB 5.0, the character ``:'` could not
appear as the third character in a packet (as it would potentially conflict with
the sequence-id).

Response data can be run-length encoded to save space. A ``*'` means that the
next character is an ASCII encoding giving a repeat count which stands for that
many repetitions of the character preceding the ``*'`. The encoding is `n+29`,
yielding a printable character where `n >=3` (which is where rle starts to win).
The printable characters ``$'`, ``#'`, ``+'` and ``-'` or with a numeric value
greater than 126 should not be used.

Some remote systems have used a different run-length encoding mechanism loosely
refered to as the cisco encoding. Following the ``*'` character are two hex
digits that indicate the size of the packet.

So:

```
"0* "

```

means the same as "0000".

The error response returned for some packets includes a two character error
number. That number is not well defined.

For any command not supported by the stub, an empty response (``$#00'`) should
be returned. That way it is possible to extend the protocol. A newer GDB can
tell if a packet is supported based on that response.

A stub is required to support the ``g'`, ``G'`, ``m'`, ``M'`, ``c'`, and ``s'`
commands. All other commands are optional.

Below is a complete list of all currently defined commands and their
corresponding response data:

|  |  |  |
| --- | --- | --- |
| Packet | Request | Description |
| extended mode | `!` | Enable extended mode. In extended mode, the remote
server is made persistent. The ``R'` packet is used to restart the program being
debugged. |
|  | reply ``OK'` | The remote target both supports and has enabled extended
mode. |
| last signal | `?` | Indicate the reason the target halted. The reply is the
same as for step and continue. |
|  | reply | see below |
| reserved | `a` | Reserved for future use |
| set program arguments **(reserved)** | `A`arglen`,`argnum`,`arg`,...` |  |
|  |  | Initialized ``argv[]'` array passed into program. arglen specifies the
number of bytes in the hex encoded byte stream arg. See `gdbserver' for more
details. |
|  | reply `OK` |
|  | reply `E`NN |
| set baud **(deprecated)** | `b`baud | Change the serial line speed to baud.
JTC: *When does the transport layer state change? When it's received, or after
the ACK is transmitted. In either case, there are problems if the command or the
acknowledgment packet is dropped.* Stan: *If people really wanted to add
something like this, and get it working for the first time, they ought to modify
ser-unix.c to send some kind of out-of-band message to a specially-setup stub
and have the switch happen "in between" packets, so that from remote protocol's
point of view, nothing actually happened.* |
| set breakpoint **(deprecated)** | `B`addr,mode | Set (mode is ``S'`) or clear
(mode is ``C'`) a breakpoint at addr. *This has been replaced by the ``Z'` and
``z'` packets.* |
| continue | `c`addr | addr is address to resume. If addr is omitted, resume at
current address. |
|  | reply | see below |
| continue with signal | `C`sig`;`addr | Continue with signal sig (hex signal
number). If `;`addr is omitted, resume at same address. |
|  | reply | see below |
| toggle debug **(deprecated)** | `d` | toggle debug flag. |
| detach | `D` | Detach GDB from the remote system. Sent to the remote target
before GDB disconnects. |
|  | reply *no response* | GDB does not check for any response after sending
this packet. |
| reserved | `e` | Reserved for future use |
| reserved | `E` | Reserved for future use |
| reserved | `f` | Reserved for future use |
| reserved | `F` | Reserved for future use |
| read registers | `g` | Read general registers. |
|  | reply XX... | Each byte of register data is described by two hex digits.
The bytes with the register are transmitted in target byte order. The size of
each register and their position within the ``g'` packet are determined by the
GDB internal macros REGISTER_RAW_SIZE and REGISTER_NAME macros. The
specification of several standard `g` packets is specified below. |
|  | `E`NN | for an error. |
| write regs | `G`XX... | See ``g'` for a description of the XX... data. |
|  | reply `OK` | for success |
|  | reply `E`NN | for an error |
| reserved | `h` | Reserved for future use |
| set thread | `H`ct... | Set thread for subsequent operations (``m'`, ``M'`,
``g'`, ``G'`, et.al.). c = ``c'` for thread used in step and continue; t... can
be -1 for all threads. c = ``g'` for thread used in other operations. If zero,
pick a thread, any thread. |
|  | reply `OK` | for success |
|  | reply `E`NN | for an error |
| cycle step **(draft)** | `i`addr`,`nnn | Step the remote target by a single
clock cycle. If `,`nnn is present, cycle step nnn cycles. If addr is present,
cycle step starting at that address. |
| signal then cycle step **(reserved)** | `I` | See ``i'` and ``S'` for likely
syntax and semantics. |
| reserved | `j` | Reserved for future use |
| reserved | `J` | Reserved for future use |
| kill request | `k` | FIXME: *There is no description of how operate when a
specific thread context has been selected (ie. does 'k' kill only that
thread?)*. |
| reserved | `l` | Reserved for future use |
| reserved | `L` | Reserved for future use |
| read memory | `m`addr`,`length | Read length bytes of memory starting at
address addr. Neither GDB nor the stub assume that sized memory transfers are
assumed using word alligned accesses. FIXME: *A word aligned memory transfer
mechanism is needed.* |
|  | reply XX... | XX... is mem contents. Can be fewer bytes than requested if
able to read only part of the data. Neither GDB nor the stub assume that sized
memory transfers are assumed using word alligned accesses. FIXME: *A word
aligned memory transfer mechanism is needed.* |
|  | reply `E`NN | NN is errno |
| write mem | `M`addr,length`:`XX... | Write length bytes of memory starting at
address addr. XX... is the data. |
|  | reply `OK` | for success |
|  | reply `E`NN | for an error (this includes the case where only part of the
data was written). |
| reserved | `n` | Reserved for future use |
| reserved | `N` | Reserved for future use |
| reserved | `o` | Reserved for future use |
| reserved | `O` | Reserved for future use |
| read reg **(reserved)** | `p`n... | See write register. |
|  | return r.... | The hex encoded value of the register in target byte order.
|
| write reg | `P`n...`=`r... | Write register n... with value r..., which
contains two hex digits for each byte in the register (target byte order). |
|  | reply `OK` | for success |
|  | reply `E`NN | for an error |
| general query | `q`query | Request info about query. In general GDB queries
have a leading upper case letter. Custom vendor queries should use a company
prefix (in lower case) ex: ``qfsf.var'`. query may optionally be followed by a
``,'` or ``;'` separated list. Stubs must ensure that they match the full query
name. |
|  | reply `XX...` | Hex encoded data from query. The reply can not be empty. |
|  | reply `E`NN | error reply |
|  | reply ``'` | Indicating an unrecognized query. |
| general set | `Q`var`=`val | Set value of var to val. See ``q'` for a
discussing of naming conventions. |
| reset **(deprecated)** | `r` | Reset the entire system. |
| remote restart | `R`XX | Restart the program being debugged. XX, while needed,
is ignored. This packet is only available in extended mode. |
|  | no reply | The ``R'` packet has no reply. |
| step | `s`addr | addr is address to resume. If addr is omitted, resume at same
address. |
|  | reply | see below |
| step with signal | `S`sig`;`addr | Like ``C'` but step not continue. |
|  | reply | see below |
| search | `t`addr`:`PP`,`MM | Search backwards starting at address addr for a
match with pattern PP and mask MM. PP and MM are 4 bytes. addr must be at least
3 digits. |
| thread alive | `T`XX | Find out if the thread XX is alive. |
|  | reply `OK` | thread is still alive |
|  | reply `E`NN | thread is dead |
| reserved | `u` | Reserved for future use |
| reserved | `U` | Reserved for future use |
| reserved | `v` | Reserved for future use |
| reserved | `V` | Reserved for future use |
| reserved | `w` | Reserved for future use |
| reserved | `W` | Reserved for future use |
| reserved | `x` | Reserved for future use |
| write mem (binary) | `X`addr`,`length:XX... | addr is address, length is
number of bytes, XX... is binary data. The characters `$`, `#`, and `0x7d` are
escaped using `0x7d`. |
|  | reply `OK` | for success |
|  | reply `E`NN | for an error |
| reserved | `y` | Reserved for future use |
| reserved | `Y` | Reserved for future use |
| remove break or watchpoint **(draft)** | `z`t`,`addr`,`length | See ``Z'`. |
| insert break or watchpoint **(draft)** | `Z`t`,`addr`,`length | t is type:
``0'` - software breakpoint, ``1'` - hardware breakpoint, ``2'` - write
watchpoint, ``3'` - read watchpoint, ``4'` - access watchpoint; addr is address;
length is in bytes. For a software breakpoint, length specifies the size of the
instruction to be patched. For hardware breakpoints and watchpoints length
specifies the memory region to be monitored. To avoid potential problems with
duplicate packets, the operations should be implemented in an idempotent way. |
|  | reply `E`NN | for an error |
|  | reply `OK` | for success |
|  | ``'` | If not supported. |
| reserved | <other> | Reserved for future use |

The ``C'`, ``c'`, ``S'`, ``s'` and ``?'` packets can receive any of the below as
a reply. In the case of the ``C'`, ``c'`, ``S'` and ``s'` packets, that reply is
only returned when the target halts. In the below the exact meaning of ``signal
number'` is poorly defined. In general one of the UNIX signal numbering
conventions is used.

|  |  |
| --- | --- |
| `S`AA | AA is the signal number |
| `T`AAn...`:`r...`;`n...`:`r...`;`n...`:`r...`;` | AA = two hex digit signal
number; n... = register number (hex), r... = target byte ordered register
contents, size defined by `REGISTER_RAW_SIZE`; n... = ``thread'`, r... = thread
process ID, this is a hex integer; n... = other string not starting with valid
hex digit. GDB should ignore this n..., r... pair and go on to the next. This
way we can extend the protocol. |
| `W`AA | The process exited, and AA is the exit status. This is only applicable
for certains sorts of targets. |
| `X`AA | The process terminated with signal AA. |
| `N`AA`;`t...`;`d...`;`b... **(obsolete)** | AA = signal number; t... = address
of symbol "_start"; d... = base of data section; b... = base of bss section.
*Note: only used by Cisco Systems targets. The difference between this reply and
the "qOffsets" query is that the 'N' packet may arrive spontaneously whereas the
'qOffsets' is a query initiated by the host debugger.* |
| `O`XX... | XX... is hex encoding of ASCII data. This can happen at any time
while the program is running and the debugger should continue to wait for 'W',
'T', etc. |

The following set and query packets have already been defined.

|  |  |  |
| --- | --- | --- |
| current thread | `q``C` | Return the current thread id. |
|  | reply `QC`pid | Where pid is a HEX encoded 16 bit process id. |
|  | reply * | Any other reply implies the old pid. |
| all thread ids | `q``fThreadInfo` |
|  | `q``sThreadInfo` | Obtain a list of active thread ids from the target (OS).
Since there may be too many active threads to fit into one reply packet, this
query works iteratively: it may require more than one query/reply sequence to
obtain the entire list of threads. The first query of the sequence will be the
`qf``ThreadInfo` query; subsequent queries in the sequence will be the
`qs``ThreadInfo` query. |
|  |  | NOTE: replaces the `qL` query (see below). |
|  | reply `m`<id> | A single thread id |
|  | reply `m`<id>,<id>... | a comma-separated list of thread ids |
|  | reply `l` | (lower case 'el') denotes end of list. |
|  |  | In response to each query, the target will reply with a list of one or
more thread ids, in big-endian hex, separated by commas. GDB will respond to
each reply with a request for more thread ids (using the `qs` form of the
query), until the target responds with `l` (lower-case el, for `'last'`). |
| extra thread info | `q``ThreadExtraInfo``,`id |  |
|  |  | Where <id> is a thread-id in big-endian hex. Obtain a printable string
description of a thread's attributes from the target OS. This string may contain
anything that the target OS thinks is interesting for GDB to tell the user about
the thread. The string is displayed in GDB's ``info threads'` display. Some
examples of possible thread extra info strings are "Runnable", or "Blocked on
Mutex". |
|  | reply XX... | Where XX... is a hex encoding of ASCII data, comprising the
printable string containing the extra information about the thread's attributes.
|
| query LIST or threadLIST **(deprecated)** |
`q``L`startflagthreadcountnextthread |  |
|  |  | Obtain thread information from RTOS. Where: startflag (one hex digit) is
one to indicate the first query and zero to indicate a subsequent query;
threadcount (two hex digits) is the maximum number of threads the response
packet can contain; and nextthread (eight hex digits), for subsequent queries
(startflag is zero), is returned in the response as argthread. |
|  |  | NOTE: this query is replaced by the `q``fThreadInfo` query (see above).
|
|  | reply `q``M`countdoneargthreadthread... |  |
|  |  | Where: count (two hex digits) is the number of threads being returned;
done (one hex digit) is zero to indicate more threads and one indicates no
further threads; argthreadid (eight hex digits) is nextthread from the request
packet; thread... is a sequence of thread IDs from the target. threadid (eight
hex digits). See `remote.c:parse_threadlist_response()`. |
| compute CRC of memory block | `q``CRC:`addr`,`length |  |
|  | reply `E`NN | An error (such as memory fault) |
|  | reply `C`CRC32 | A 32 bit cyclic redundancy check of the specified memory
region. |
| query sect offs | `q``Offsets` | Get section offsets that the target used when
re-locating the downloaded image. *Note: while a `Bss` offset is included in the
response, GDB ignores this and instead applies the `Data` offset to the `Bss`
section.* |
|  | reply `Text=`xxx`;Data=`yyy`;Bss=`zzz |
| thread info request | `q``P`modethreadid |  |
|  |  | Returns information on threadid. Where: mode is a hex encoded 32 bit
mode; threadid is a hex encoded 64 bit thread ID. |
|  | reply * | See `remote.c:remote_unpack_thread_info_response()`. |
| remote command | `q``Rcmd,`COMMAND |  |
|  |  | COMMAND (hex encoded) is passed to the local interpreter for execution.
Invalid commands should be reported using the output string. Before the final
result packet, the target may also respond with a number of intermediate
`O`OUTPUT console output packets. *Implementors should note that providing
access to a stubs's interpreter may have security implications*. |
|  | reply `OK` | A command response with no output. |
|  | reply OUTPUT | A command response with the hex encoded output string
OUTPUT. |
|  | reply `E`NN | Indicate a badly formed request. |
|  | reply ``'` | When ``q'```Rcmd'` is not recognized. |
| symbol lookup | `qSymbol::` | Notify the target that GDB is prepared to serve
symbol lookup requests. Accept requests from the target for the values of
symbols. |
|  |  |  |
|  | reply `OK` | The target does not need to look up any (more) symbols. |
|  | reply `qSymbol:`sym_name | The target requests the value of symbol sym_name
(hex encoded). GDB may provide the value by using the
`qSymbol:`sym_value:sym_name message, described below. |
| symbol value | `qSymbol:`sym_value:sym_name | Set the value of SYM_NAME to
SYM_VALUE. |
|  |  | sym_name (hex encoded) is the name of a symbol whose value the target
has previously requested. |
|  |  | sym_value (hex) is the value for symbol sym_name. If GDB cannot supply a
value for sym_name, then this field will be empty. |
|  | reply `OK` | The target does not need to look up any (more) symbols. |
|  | reply `qSymbol:`sym_name | The target requests the value of a new symbol
sym_name (hex encoded). GDB will continue to supply the values of symbols (if
available), until the target ceases to request them. |

The following ``g'`/``G'` packets have previously been defined. In the below,
some thirty-two bit registers are transferred as sixty-four bits. Those
registers should be zero/sign extended (which?) to fill the space allocated.
Register bytes are transfered in target byte order. The two nibbles within a
register byte are transfered most-significant - least-significant.

|  |  |
| --- | --- |
| MIPS32 | All registers are transfered as thirty-two bit quantities in the
order: 32 general-purpose; sr; lo; hi; bad; cause; pc; 32 floating-point
registers; fsr; fir; fp. |
| MIPS64 | All registers are transfered as sixty-four bit quantities (including
thirty-two bit registers such as `sr`). The ordering is the same as `MIPS32`. |

Example sequence of a target being re-started. Notice how the restart does not
get any direct output:

```
<- R00
-> +
target restarts
<- ?
-> +
-> T001:1234123412341234
<- +

```

Example sequence of a target being stepped by a single instruction:

```
<- G1445...
-> +
<- s
-> +
time passes
-> T001:1234123412341234
<- +
<- g
-> +
-> 1455...
<- +

```

---

Go to the [first](gdb_1.html), [previous](gdb_128.html), [next](gdb_130.html),
[last](gdb_268.html) section, [table of contents](gdb_toc.html).