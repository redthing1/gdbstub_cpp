# Debugging with gdb - gdb Remote Serial Protocol

Go to the [first](gdb_1.html), [previous](gdb_32.html), [next](gdb_34.html), [last](gdb_36.html) section, [table of contents](gdb_toc.html).

---

## [Overview](about:blank/gdb_toc.html#TOC303)

There may be occasions when you need to know something about the protocol--for
example, if there is only one serial port to your target machine, you might want
your program to do something special if it recognizes a packet meant for GDB.

In the examples below, ``->'` and ``<-'` are used to indicate transmitted and
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
-> $packet-data#checksum
<- +

```

The host (GDB) sends commands, and the target (the debugging stub incorporated
in your program) sends a response. In the case of step and continue commands,
the response is only sent when the operation has completed (the target has again
stopped).

packet-data consists of a sequence of characters with the exception of ``#'` and
``$'` (see ``X'` packet for additional exceptions).

Fields within the packet should be separated using ``,'` ``;'` or  ``:'`. Except
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

## [Packets](about:blank/gdb_toc.html#TOC304)

The following table provides a complete list of all currently defined commands
and their corresponding response data. See section [File-I/O remote protocol
extension](about:blank/gdb_33.html#SEC309), for details about the File I/O
extension of the remote protocol.

`!` -- extended mode
:   Enable extended mode. In extended mode, the remote server is made persistent. The ``R'` packet is used to restart the program being debugged. Reply:

    ``OK'`
    :   The remote target both supports and has enabled extended mode.

`?` -- last signal
:   Indicate the reason the target halted. The reply is the same as for step and continue. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`a` -- reserved
:   Reserved for future use.

`A`arglen`,`argnum`,`arg`,...` -- set program arguments **(reserved)**
:   Initialized ``argv[]'` array passed into program. arglen specifies the number of bytes in the hex encoded byte stream arg. See `gdbserver` for more details. Reply:

    ``OK'`

    ``ENN'`

`b`baud -- set baud **(deprecated)**
:   Change the serial line speed to baud. JTC: *When does the transport layer state change? When it's received, or after the ACK is transmitted. In either case, there are problems if the command or the acknowledgment packet is dropped.* Stan: *If people really wanted to add something like this, and get it working for the first time, they ought to modify ser-unix.c to send some kind of out-of-band message to a specially-setup stub and have the switch happen "in between" packets, so that from remote protocol's point of view, nothing actually happened.*

`B`addr,mode -- set breakpoint **(deprecated)**
:   Set (mode is ``S'`) or clear (mode is ``C'`) a breakpoint at addr. This packet has been replaced by the ``Z'` and ``z'` packets (@xref{insert breakpoint or watchpoint packet}).

`c`addr -- continue
:   addr is address to resume. If addr is omitted, resume at current address. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`C`sig`;`addr -- continue with signal
:   Continue with signal sig (hex signal number). If `;`addr is omitted, resume at same address. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`d` -- toggle debug **(deprecated)**
:   Toggle debug flag.

`D` -- detach
:   Detach GDB from the remote system. Sent to the remote target before GDB disconnects via the `detach` command. Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error

`e` -- reserved
:   Reserved for future use.

`E` -- reserved
:   Reserved for future use.

`f` -- reserved
:   Reserved for future use.

`F`RC`,`EE`,`CF`;`XX -- Reply to target's F packet.
:   This packet is send by GDB as reply to a `F` request packet sent by the target. This is part of the File-I/O protocol extension. See section [File-I/O remote protocol extension](about:blank/gdb_33.html#SEC309), for the specification.

`g` -- read registers
:   @anchor{read registers packet}  Read general registers. Reply:

    ``XX...'`
    :   Each byte of register data is described by two hex digits. The bytes with the register are transmitted in target byte order. The size of each register and their position within the ``g'` packet are determined by the GDB internal macros DEPRECATED_REGISTER_RAW_SIZE and REGISTER_NAME macros. The specification of several standard `g` packets is specified below.

    ``ENN'`
    :   for an error.

`G`XX... -- write regs
:   @xref{read registers packet}, for a description of the XX... data. Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error

`h` -- reserved
:   Reserved for future use.

`H`ct... -- set thread
:   Set thread for subsequent operations (``m'`, ``M'`, ``g'`, ``G'`, et.al.). c depends on the operation to be performed: it should be ``c'` for step and continue operations, ``g'` for other operations. The thread designator t... may be -1, meaning all the threads, a thread number, or zero which means pick any thread. Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error

`i`addr`,`nnn -- cycle step **(draft)**
:   @anchor{cycle step packet}  Step the remote target by a single clock cycle. If `,`nnn is present, cycle step nnn cycles. If addr is present, cycle step starting at that address.

`I` -- signal then cycle step **(reserved)**
:   @xref{step with signal packet}. @xref{cycle step packet}.

`j` -- reserved
:   Reserved for future use.

`J` -- reserved
:   Reserved for future use.

`k` -- kill request
:   FIXME: *There is no description of how to operate when a specific thread context has been selected (i.e. does 'k' kill only that thread?)*.

`K` -- reserved
:   Reserved for future use.

`l` -- reserved
:   Reserved for future use.

`L` -- reserved
:   Reserved for future use.

`m`addr`,`length -- read memory
:   Read length bytes of memory starting at address addr. Neither GDB nor the stub assume that sized memory transfers are assumed using word aligned accesses. FIXME: *A word aligned memory transfer mechanism is needed.* Reply:

    ``XX...'`
    :   XX... is mem contents. Can be fewer bytes than requested if able to read only part of the data. Neither GDB nor the stub assume that sized memory transfers are assumed using word aligned accesses. FIXME: *A word aligned memory transfer mechanism is needed.*

    ``ENN'`
    :   NN is errno

`M`addr,length`:`XX... -- write mem
:   Write length bytes of memory starting at address addr. XX... is the data. Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error (this includes the case where only part of the data was written).

`n` -- reserved
:   Reserved for future use.

`N` -- reserved
:   Reserved for future use.

`o` -- reserved
:   Reserved for future use.

`O` -- reserved

`p`hex number of register -- read register packet
:   @xref{read registers packet}, for a description of how the returned register value is encoded. Reply:

    ``XX...'`
    :   the register's value

    ``ENN'`
    :   for an error

    ``'`
    :   Indicating an unrecognized query.

`P`n...`=`r... -- write register
:   @anchor{write register packet}  Write register n... with value r..., which contains two hex digits for each byte in the register (target byte order). Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error

`q`query -- general query
:   @anchor{general query packet}  Request info about query. In general GDB queries have a leading upper case letter. Custom vendor queries should use a company prefix (in lower case) ex: ``qfsf.var'`. query may optionally be followed by a ``,'` or ``;'` separated list. Stubs must ensure that they match the full query name. Reply:

    ``XX...'`
    :   Hex encoded data from query. The reply can not be empty.

    ``ENN'`
    :   error reply

    ``'`
    :   Indicating an unrecognized query.

`Q`var`=`val -- general set
:   Set value of var to val. @xref{general query packet}, for a discussion of naming conventions.

`r` -- reset **(deprecated)**
:   Reset the entire system.

`R`XX -- remote restart
:   Restart the program being debugged. XX, while needed, is ignored. This packet is only available in extended mode. Reply:

    ``no reply'`
    :   The ``R'` packet has no reply.

`s`addr -- step
:   addr is address to resume. If addr is omitted, resume at same address. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`S`sig`;`addr -- step with signal
:   @anchor{step with signal packet}  Like ``C'` but step not continue. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`t`addr`:`PP`,`MM -- search
:   Search backwards starting at address addr for a match with pattern PP and mask MM. PP and MM are 4 bytes. addr must be at least 3 digits.

`T`XX -- thread alive
:   Find out if the thread XX is alive. Reply:

    ``OK'`
    :   thread is still alive

    ``ENN'`
    :   thread is dead

`u` -- reserved
:   Reserved for future use.

`U` -- reserved
:   Reserved for future use.

`v` -- verbose packet prefix
:   Packets starting with `v` are identified by a multi-letter name, up to the first `;` or `?` (or the end of the packet).

`vCont`[;action[`:`tid]]... -- extended resume
:   Resume the inferior. Different actions may be specified for each thread. If an action is specified with no tid, then it is applied to any threads that don't have a specific action specified; if no default action is specified then other threads should remain stopped. Specifying multiple default actions is an error; specifying no actions is also an error. Thread IDs are specified in hexadecimal. Currently supported actions are:

    `c`
    :   Continue.

    `Csig`
    :   Continue with signal sig. sig should be two hex digits.

    `s`
    :   Step.

    `Ssig`
    :   Step with signal sig. sig should be two hex digits.

    The optional addr argument normally associated with these packets is not supported in `vCont`. Reply: See section [Stop Reply Packets](about:blank/gdb_33.html#SEC305), for the reply specifications.

`vCont?` -- extended resume query
:   Query support for the `vCont` packet. Reply:

    ``vCont[;action]...'`
    :   The `vCont` packet is supported. Each action is a supported command in the `vCont` packet.

    ``'`
    :   The `vCont` packet is not supported.

`V` -- reserved
:   Reserved for future use.

`w` -- reserved
:   Reserved for future use.

`W` -- reserved
:   Reserved for future use.

`x` -- reserved
:   Reserved for future use.

`X`addr`,`length:XX... -- write mem (binary)
:   addr is address, length is number of bytes, XX... is binary data. The characters `$`, `#`, and `0x7d` are escaped using `0x7d`, and then XORed with `0x20`. For example, `0x7d` would be transmitted as `0x7d 0x5d`. Reply:

    ``OK'`
    :   for success

    ``ENN'`
    :   for an error

`y` -- reserved
:   Reserved for future use.

`Y` reserved
:   Reserved for future use.

`z`type`,`addr`,`length -- remove breakpoint or watchpoint **(draft)**

`Z`type`,`addr`,`length -- insert breakpoint or watchpoint **(draft)**
:   @anchor{insert breakpoint or watchpoint packet}   Insert (`Z`) or remove (`z`) a type breakpoint or watchpoint starting at address address and covering the next length bytes. Each breakpoint and watchpoint packet type is documented separately. *Implementation notes: A remote target shall return an empty string for an unrecognized breakpoint or watchpoint packet type. A remote target shall support either both or neither of a given `Z`type... and `z`type... packet pair. To avoid potential problems with duplicate packets, the operations should be implemented in an idempotent way.*

`z``0``,`addr`,`length -- remove memory breakpoint **(draft)**

`Z``0``,`addr`,`length -- insert memory breakpoint **(draft)**
:   Insert (`Z0`) or remove (`z0`) a memory breakpoint at address `addr` of size `length`. A memory breakpoint is implemented by replacing the instruction at addr with a software breakpoint or trap instruction. The `length` is used by targets that indicates the size of the breakpoint (in bytes) that should be inserted (e.g., the ARM and MIPS can insert either a 2 or 4 byte breakpoint). *Implementation note: It is possible for a target to copy or move code that contains memory breakpoints (e.g., when implementing overlays). The behavior of this packet, in the presence of such a target, is not defined.* Reply:

    ``OK'`
    :   success

    ``'`
    :   not supported

    ``ENN'`
    :   for an error

`z``1``,`addr`,`length -- remove hardware breakpoint **(draft)**

`Z``1``,`addr`,`length -- insert hardware breakpoint **(draft)**
:   Insert (`Z1`) or remove (`z1`) a hardware breakpoint at address `addr` of size `length`. A hardware breakpoint is implemented using a mechanism that is not dependant on being able to modify the target's memory. *Implementation note: A hardware breakpoint is not affected by code movement.* Reply:

    ``OK'`
    :   success

    ``'`
    :   not supported

    ``ENN'`
    :   for an error

`z``2``,`addr`,`length -- remove write watchpoint **(draft)**

`Z``2``,`addr`,`length -- insert write watchpoint **(draft)**
:   Insert (`Z2`) or remove (`z2`) a write watchpoint. Reply:

    ``OK'`
    :   success

    ``'`
    :   not supported

    ``ENN'`
    :   for an error

`z``3``,`addr`,`length -- remove read watchpoint **(draft)**

`Z``3``,`addr`,`length -- insert read watchpoint **(draft)**
:   Insert (`Z3`) or remove (`z3`) a read watchpoint. Reply:

    ``OK'`
    :   success

    ``'`
    :   not supported

    ``ENN'`
    :   for an error

`z``4``,`addr`,`length -- remove access watchpoint **(draft)**

`Z``4``,`addr`,`length -- insert access watchpoint **(draft)**
:   Insert (`Z4`) or remove (`z4`) an access watchpoint. Reply:

    ``OK'`
    :   success

    ``'`
    :   not supported

    ``ENN'`
    :   for an error

## [Stop Reply Packets](about:blank/gdb_toc.html#TOC305)

The ``C'`, ``c'`, ``S'`, ``s'` and ``?'` packets can receive any of the below as
a reply. In the case of the ``C'`, ``c'`, ``S'` and ``s'` packets, that reply is
only returned when the target halts. In the below the exact meaning of ``signal
number'` is poorly defined. In general one of the UNIX signal numbering
conventions is used.

``SAA'`
:   AA is the signal number

``TAAn...:r...;n...:r...;n...:r...;'`
:   AA = two hex digit signal number; n... = register number (hex), r... = target byte ordered register contents, size defined by `DEPRECATED_REGISTER_RAW_SIZE`; n... = ``thread'`, r... = thread process ID, this is a hex integer; n... = (``watch'` | ``rwatch'` | ``awatch'`, r... = data address, this is a hex integer; n... = other string not starting with valid hex digit. GDB should ignore this n..., r... pair and go on to the next. This way we can extend the protocol.

``WAA'`
:   The process exited, and AA is the exit status. This is only applicable to certain targets.

``XAA'`
:   The process terminated with signal AA.

``OXX...'`
:   XX... is hex encoding of ASCII data. This can happen at any time while the program is running and the debugger should continue to wait for ``W'`, ``T'`, etc.

``Fcall-id,parameter...'`
:   call-id is the identifier which says which host system call should be called. This is just the name of the function. Translation into the correct system call is only applicable as it's defined in GDB. See section [File-I/O remote protocol extension](about:blank/gdb_33.html#SEC309), for a list of implemented system calls. parameter... is a list of parameters as defined for this very system call. The target replies with this packet when it expects GDB to call a host system call on behalf of the target. GDB replies with an appropriate `F` packet and keeps up waiting for the next reply packet from the target. The latest ``C'`, ``c'`, ``S'` or ``s'` action is expected to be continued. See section [File-I/O remote protocol extension](about:blank/gdb_33.html#SEC309), for more details.

## [General Query Packets](about:blank/gdb_toc.html#TOC306)

The following set and query packets have already been defined.

`q``C` -- current thread
:   Return the current thread id. Reply:

    ``QCpid'`
    :   Where pid is an unsigned hexidecimal process id.

    ``*'`
    :   Any other reply implies the old pid.

`q``fThreadInfo` -- all thread ids
:   `q``sThreadInfo` Obtain a list of active thread ids from the target (OS). Since there may be too many active threads to fit into one reply packet, this query works iteratively: it may require more than one query/reply sequence to obtain the entire list of threads. The first query of the sequence will be the `qf``ThreadInfo` query; subsequent queries in the sequence will be the `qs``ThreadInfo` query. NOTE: replaces the `qL` query (see below). Reply:

    ``mid'`
    :   A single thread id

    ``mid,id...'`
    :   a comma-separated list of thread ids

    ``l'`
    :   (lower case 'el') denotes end of list.

    In response to each query, the target will reply with a list of one or more thread ids, in big-endian unsigned hex, separated by commas. GDB will respond to each reply with a request for more thread ids (using the `qs` form of the query), until the target responds with `l` (lower-case el, for `'last'`).

`q``ThreadExtraInfo``,`id -- extra thread info
:   Where id is a thread-id in big-endian hex. Obtain a printable string description of a thread's attributes from the target OS. This string may contain anything that the target OS thinks is interesting for GDB to tell the user about the thread. The string is displayed in GDB's ``info threads'` display. Some examples of possible thread extra info strings are "Runnable", or "Blocked on Mutex". Reply:

    ``XX...'`
    :   Where XX... is a hex encoding of ASCII data, comprising the printable string containing the extra information about the thread's attributes.

`q``L`startflagthreadcountnextthread -- query LIST or threadLIST **(deprecated)**
:   Obtain thread information from RTOS. Where: startflag (one hex digit) is one to indicate the first query and zero to indicate a subsequent query; threadcount (two hex digits) is the maximum number of threads the response packet can contain; and nextthread (eight hex digits), for subsequent queries (startflag is zero), is returned in the response as argthread. NOTE: this query is replaced by the `q``fThreadInfo` query (see above). Reply:

    ``qMcountdoneargthreadthread...'`
    :   Where: count (two hex digits) is the number of threads being returned; done (one hex digit) is zero to indicate more threads and one indicates no further threads; argthreadid (eight hex digits) is nextthread from the request packet; thread... is a sequence of thread IDs from the target. threadid (eight hex digits). See `remote.c:parse_threadlist_response()`.

`q``CRC:`addr`,`length -- compute CRC of memory block
:   Reply:

    ``ENN'`
    :   An error (such as memory fault)

    ``CCRC32'`
    :   A 32 bit cyclic redundancy check of the specified memory region.

`q``Offsets` -- query sect offs
:   Get section offsets that the target used when re-locating the downloaded image. *Note: while a `Bss` offset is included in the response, GDB ignores this and instead applies the `Data` offset to the `Bss` section.* Reply:

    ``Text=xxx;Data=yyy;Bss=zzz'`

`q``P`modethreadid -- thread info request
:   Returns information on threadid. Where: mode is a hex encoded 32 bit mode; threadid is a hex encoded 64 bit thread ID. Reply:

    ``*'`

    See `remote.c:remote_unpack_thread_info_response()`.

`q``Rcmd,`command -- remote command
:   command (hex encoded) is passed to the local interpreter for execution. Invalid commands should be reported using the output string. Before the final result packet, the target may also respond with a number of intermediate `O`output console output packets. *Implementors should note that providing access to a stubs's interpreter may have security implications*. Reply:

    ``OK'`
    :   A command response with no output.

    ``OUTPUT'`
    :   A command response with the hex encoded output string OUTPUT.

    ``ENN'`
    :   Indicate a badly formed request.

    ```''`
    :   When ``q'```Rcmd'` is not recognized.

    z

`qSymbol::` -- symbol lookup
:   Notify the target that GDB is prepared to serve symbol lookup requests. Accept requests from the target for the values of symbols. Reply:

    ``OK'`
    :   The target does not need to look up any (more) symbols.

    ``qSymbol:sym_name'`
    :   The target requests the value of symbol sym_name (hex encoded). GDB may provide the value by using the `qSymbol:`sym_value:sym_name message, described below.

`qSymbol:`sym_value:sym_name -- symbol value
:   Set the value of sym_name to sym_value. sym_name (hex encoded) is the name of a symbol whose value the target has previously requested. sym_value (hex) is the value for symbol sym_name. If GDB cannot supply a value for sym_name, then this field will be empty. Reply:

    ``OK'`
    :   The target does not need to look up any (more) symbols.

    ``qSymbol:sym_name'`
    :   The target requests the value of a new symbol sym_name (hex encoded). GDB will continue to supply the values of symbols (if available), until the target ceases to request them.

`qPart`:object:`read`:annex:offset,length -- read special data
:   Read uninterpreted bytes from the target's special data area identified by the keyword `object`. Request length bytes starting at offset bytes into the data. The content and encoding of annex is specific to the object; it can supply additional details about what data to access. Here are the specific requests of this form defined so far. All ``qPart:object:read:...'` requests use the same reply formats, listed below.

    `qPart`:`auxv`:`read`::offset,length
    :   Access the target's **auxiliary vector**. See section [Operating system auxiliary information](about:blank/gdb_9.html#SEC69), and see section [Remote configuration](about:blank/gdb_18.html#SEC160). Note annex must be empty.

    Reply:

    `OK`
    :   The offset in the request is at the end of the data. There is no more data to be read.

    XX...
    :   Hex encoded data bytes read. This may be fewer bytes than the length in the request.

    `E00`
    :   The request was malformed, or annex was invalid.

    `E`nn
    :   The offset was invalid, or there was an error encountered reading the data. nn is a hex-encoded `errno` value.

    `""` (empty)
    :   An empty reply indicates the object or annex string was not recognized by the stub.

`qPart`:object:`write`:annex:offset:data...
:   Write uninterpreted bytes into the target's special data area identified by the keyword `object`, starting at offset bytes into the data. data... is the hex-encoded data to be written. The content and encoding of annex is specific to the object; it can supply additional details about what data to access. No requests of this form are presently in use. This specification serves as a placeholder to document the common format that new specific request specifications ought to use. Reply:

    nn
    :   nn (hex encoded) is the number of bytes written. This may be fewer bytes than supplied in the request.

    `E00`
    :   The request was malformed, or annex was invalid.

    `E`nn
    :   The offset was invalid, or there was an error encountered writing the data. nn is a hex-encoded `errno` value.

    `""` (empty)
    :   An empty reply indicates the object or annex string was not recognized by the stub, or that the object does not support writing.

`qPart`:object:operation:...
:   Requests of this form may be added in the future. When a stub does not recognize the object keyword, or its support for object does not recognize the operation keyword, the stub must respond with an empty packet.

`qGetTLSAddr`:thread-id,offset,lm -- get thread local storage address
:   Fetch the address associated with thread local storage specified by thread-id, offset, and lm. thread-id is the (big endian, hex encoded) thread id associated with the thread for which to fetch the TLS address. offset is the (big endian, hex encoded) offset associated with the thread local variable. (This offset is obtained from the debug information associated with the variable.) lm is the (big endian, hex encoded) OS/ABI specific encoding of the the load module associated with the thread local storage. For example, a GNU/Linux system will pass the link map address of the shared object associated with the thread local storage under consideration. Other operating environments may choose to represent the load module differently, so the precise meaning of this parameter will vary. Reply:

    XX...
    :   Hex encoded (big endian) bytes representing the address of the thread local storage requested.

    `E`nn (where nn are hex digits)
    :   An error occurred.

    `""` (empty)
    :   An empty reply indicates that `qGetTLSAddr` is not supported by the stub.

    Use of this request packet is controlled by the `set remote get-thread-local-storage-address` command (see section [Remote configuration](about:blank/gdb_18.html#SEC160)).

## [Register Packet Format](about:blank/gdb_toc.html#TOC307)

The following ``g'`/``G'` packets have previously been defined. In the below,
some thirty-two bit registers are transferred as sixty-four bits. Those
registers should be zero/sign extended (which?) to fill the space allocated.
Register bytes are transfered in target byte order. The two nibbles within a
register byte are transfered most-significant - least-significant.

MIPS32
:   All registers are transfered as thirty-two bit quantities in the order: 32 general-purpose; sr; lo; hi; bad; cause; pc; 32 floating-point registers; fsr; fir; fp.

MIPS64
:   All registers are transfered as sixty-four bit quantities (including thirty-two bit registers such as `sr`). The ordering is the same as `MIPS32`.

## [Examples](about:blank/gdb_toc.html#TOC308)

Example sequence of a target being re-started. Notice how the restart does not
get any direct output:

```
-> R00
<- +
target restarts
-> ?
<- +
<- T001:1234123412341234
-> +

```

Example sequence of a target being stepped by a single instruction:

```
-> G1445...
<- +
-> s
<- +
time passes
<- T001:1234123412341234
-> +
-> g
<- +
<- 1455...
-> +

```

## [File-I/O remote protocol extension](about:blank/gdb_toc.html#TOC309)

### [File-I/O Overview](about:blank/gdb_toc.html#TOC310)

The **File I/O remote protocol extension** (short: File-I/O) allows the target
to use the host's file system and console I/O when calling various system calls.
System calls on the target system are translated into a remote protocol packet
to the host system which then performs the needed actions and returns with an
adequate response packet to the target system. This simulates file system
operations even on targets that lack file systems.

The protocol is defined host- and target-system independent. It uses its own
independent representation of datatypes and values. Both, GDB and the target's
GDB stub are responsible for translating the system dependent values into the
unified protocol values when data is transmitted.

The communication is synchronous. A system call is possible only when GDB is
waiting for the ``C'`, ``c'`, ``S'` or ``s'` packets. While GDB handles the
request for a system call, the target is stopped to allow deterministic access
to the target's memory. Therefore File-I/O is not interuptible by target
signals. It is possible to interrupt File-I/O by a user interrupt (Ctrl-C),
though.

The target's request to perform a host system call does not finish the latest
``C'`, ``c'`, ``S'` or ``s'` action. That means, after finishing the system
call, the target returns to continuing the previous activity (continue, step).
No additional continue or step request from GDB is required.

```
(gdb) continue
  <- target requests 'system call X'
  target is stopped, GDB executes system call
  -> GDB returns result
  ... target continues, GDB returns to wait for the target
  <- target hits breakpoint and sends a Txx packet

```

The protocol is only used for files on the host file system and for I/O on the
console. Character or block special devices, pipes, named pipes or sockets or
any other communication method on the host system are not supported by this
protocol.

### [Protocol basics](about:blank/gdb_toc.html#TOC311)

The File-I/O protocol uses the `F` packet, as request as well as as reply
packet. Since a File-I/O system call can only occur when GDB is waiting for the
continuing or stepping target, the File-I/O request is a reply that GDB has to
expect as a result of a former ``C'`, ``c'`, ``S'` or ``s'` packet. This `F`
packet contains all information needed to allow GDB to call the appropriate host
system call:

- A unique identifier for the requested system call.
- All parameters to the system call. Pointers are given as addresses in the target memory address space. Pointers to strings are given as pointer/length pair. Numerical values are given as they are. Numerical control values are given in a protocol specific representation.

At that point GDB has to perform the following actions.

- If parameter pointer values are given, which point to data needed as input to a system call, GDB requests this data from the target with a standard `m` packet request. This additional communication has to be expected by the target implementation and is handled as any other `m` packet.
- GDB translates all value from protocol representation to host representation as needed. Datatypes are coerced into the host types.
- GDB calls the system call
- It then coerces datatypes back to protocol representation.
- If pointer parameters in the request packet point to buffer space in which a system call is expected to copy data to, the data is transmitted to the target using a `M` or `X` packet. This packet has to be expected by the target implementation and is handled as any other `M` or `X` packet.

Eventually GDB replies with another `F` packet which contains all necessary
information for the target to continue. This at least contains

- Return value.
- `errno`, if has been changed by the system call.
- "Ctrl-C" flag.

After having done the needed type and value coercion, the target continues the
latest continue or step action.

### [The `F` request packet](about:blank/gdb_toc.html#TOC312)

The `F` request packet has the following format:

```
Fcall-id,parameter...

```

call-id is the identifier to indicate the host system call to be called. This is just the name of the function. parameter... are the parameters to the system call.

Parameters are hexadecimal integer values, either the real values in case of
scalar datatypes, as pointers to target buffer space in case of compound
datatypes and unspecified memory areas or as pointer/length pairs in case of
string parameters. These are appended to the call-id, each separated from its
predecessor by a comma. All values are transmitted in ASCII string
representation, pointer/length pairs separated by a slash.

### [The `F` reply packet](about:blank/gdb_toc.html#TOC313)

The `F` reply packet has the following format:

```
Fretcode,errno,Ctrl-C flag;call specific attachment

```

retcode is the return code of the system call as hexadecimal value. errno is the errno set by the call, in protocol specific representation. This parameter can be omitted if the call was successful. Ctrl-C flag is only send if the user requested a break. In this case, errno must be send as well, even if the call was successful. The Ctrl-C flag itself consists of the character 'C':

```
F0,0,C

```

or, if the call was interupted before the host call has been performed:

```
F-1,4,C

```

assuming 4 is the protocol specific representation of `EINTR`.

### [Memory transfer](about:blank/gdb_toc.html#TOC314)

Structured data which is transferred using a memory read or write as e.g. a
`struct stat` is expected to be in a protocol specific format with all scalar
multibyte datatypes being big endian. This should be done by the target before
the `F` packet is sent resp. by GDB before it transfers memory to the target.
Transferred pointers to structured data should point to the already coerced data
at any time.

### [The Ctrl-C message](about:blank/gdb_toc.html#TOC315)

A special case is, if the Ctrl-C flag is set in the GDB reply packet. In this
case the target should behave, as if it had gotten a break message. The meaning
for the target is "system call interupted by `SIGINT`". Consequentially, the
target should actually stop (as with a break message) and return to GDB with a
`T02` packet. In this case, it's important for the target to know, in which
state the system call was interrupted. Since this action is by design not an
atomic operation, we have to differ between two cases:

- The system call hasn't been performed on the host yet.
- The system call on the host has been finished.

These two states can be distinguished by the target by the value of the returned
`errno`. If it's the protocol representation of `EINTR`, the system call hasn't
been performed. This is equivalent to the `EINTR` handling on POSIX systems. In
any other case, the target may presume that the system call has been finished --
successful or not -- and should behave as if the break message arrived right
after the system call.

GDB must behave reliable. If the system call has not been called yet, GDB may
send the `F` reply immediately, setting `EINTR` as `errno` in the packet. If the
system call on the host has been finished before the user requests a break, the
full action must be finshed by GDB. This requires sending `M` or `X` packets as
they fit. The `F` packet may only be send when either nothing has happened or
the full action has been completed.

### [Console I/O](about:blank/gdb_toc.html#TOC316)

By default and if not explicitely closed by the target system, the file
descriptors 0, 1 and 2 are connected to the GDB console. Output on the GDB
console is handled as any other file output operation (`write(1, ...)` or
`write(2, ...)`). Console input is handled by GDB so that after the target read
request from file descriptor 0 all following typing is buffered until either one
of the following conditions is met:

- The user presses `Ctrl-C`. The behaviour is as explained above, the `read` system call is treated as finished.
- The user presses `Enter`. This is treated as end of input with a trailing line feed.
- The user presses `Ctrl-D`. This is treated as end of input. No trailing character, especially no Ctrl-D is appended to the input.

If the user has typed more characters as fit in the buffer given to the read
call, the trailing characters are buffered in GDB until either another `read(0,
...)` is requested by the target or debugging is stopped on users request.

### [The ``isatty'` function call](about:blank/gdb_toc.html#TOC317)

A special case in this protocol is the library call `isatty` which is
implemented as its own call inside of this protocol. It returns 1 to the target
if the file descriptor given as parameter is attached to the GDB console, 0
otherwise. Implementing through system calls would require implementing `ioctl`
and would be more complex than needed.

### [The ``system'` function call](about:blank/gdb_toc.html#TOC318)

The other special case in this protocol is the `system` call which is
implemented as its own call, too. GDB is taking over the full task of calling
the necessary host calls to perform the `system` call. The return value of
`system` is simplified before it's returned to the target. Basically, the only
signal transmitted back is `EINTR` in case the user pressed `Ctrl-C`. Otherwise
the return value consists entirely of the exit status of the called command.

Due to security concerns, the `system` call is by default refused by GDB. The
user has to allow this call explicitly with the `set remote system-call-allowed
1` command.

`set remote system-call-allowed`
:   Control whether to allow the `system` calls in the File I/O protocol for the remote target. The default is zero (disabled).

`show remote system-call-allowed`
:   Show the current setting of system calls for the remote File I/O protocol.

### [List of supported calls](about:blank/gdb_toc.html#TOC319)

#### [open](about:blank/gdb_toc.html#TOC320)

```
Synopsis:
int open(const char *pathname, int flags);
int open(const char *pathname, int flags, mode_t mode);

Request:
Fopen,pathptr/len,flags,mode

```

`flags` is the bitwise or of the following values:

`O_CREAT`
:   If the file does not exist it will be created. The host rules apply as far as file ownership and time stamps are concerned.

`O_EXCL`
:   When used with O_CREAT, if the file already exists it is an error and open() fails.

`O_TRUNC`
:   If the file already exists and the open mode allows writing (O_RDWR or O_WRONLY is given) it will be truncated to length 0.

`O_APPEND`
:   The file is opened in append mode.

`O_RDONLY`
:   The file is opened for reading only.

`O_WRONLY`
:   The file is opened for writing only.

`O_RDWR`
:   The file is opened for reading and writing. Each other bit is silently ignored.

`mode` is the bitwise or of the following values:

`S_IRUSR`
:   User has read permission.

`S_IWUSR`
:   User has write permission.

`S_IRGRP`
:   Group has read permission.

`S_IWGRP`
:   Group has write permission.

`S_IROTH`
:   Others have read permission.

`S_IWOTH`
:   Others have write permission. Each other bit is silently ignored.

```
Return value:
open returns the new file descriptor or -1 if an error
occured.

Errors:

```

`EEXIST`
:   pathname already exists and O_CREAT and O_EXCL were used.

`EISDIR`
:   pathname refers to a directory.

`EACCES`
:   The requested access is not allowed.

`ENAMETOOLONG`
:   pathname was too long.

`ENOENT`
:   A directory component in pathname does not exist.

`ENODEV`
:   pathname refers to a device, pipe, named pipe or socket.

`EROFS`
:   pathname refers to a file on a read-only filesystem and write access was requested.

`EFAULT`
:   pathname is an invalid pointer value.

`ENOSPC`
:   No space on device to create the file.

`EMFILE`
:   The process already has the maximum number of files open.

`ENFILE`
:   The limit on the total number of files open on the system has been reached.

`EINTR`
:   The call was interrupted by the user.

#### [close](about:blank/gdb_toc.html#TOC321)

```
Synopsis:
int close(int fd);

Request:
Fclose,fd

Return value:
close returns zero on success, or -1 if an error occurred.

Errors:

```

`EBADF`
:   fd isn't a valid open file descriptor.

`EINTR`
:   The call was interrupted by the user.

#### [read](about:blank/gdb_toc.html#TOC322)

```
Synopsis:
int read(int fd, void *buf, unsigned int count);

Request:
Fread,fd,bufptr,count

Return value:
On success, the number of bytes read is returned.
Zero indicates end of file.  If count is zero, read
returns zero as well.  On error, -1 is returned.

Errors:

```

`EBADF`
:   fd is not a valid file descriptor or is not open for reading.

`EFAULT`
:   buf is an invalid pointer value.

`EINTR`
:   The call was interrupted by the user.

#### [write](about:blank/gdb_toc.html#TOC323)

```
Synopsis:
int write(int fd, const void *buf, unsigned int count);

Request:
Fwrite,fd,bufptr,count

Return value:
On success, the number of bytes written are returned.
Zero indicates nothing was written.  On error, -1
is returned.

Errors:

```

`EBADF`
:   fd is not a valid file descriptor or is not open for writing.

`EFAULT`
:   buf is an invalid pointer value.

`EFBIG`
:   An attempt was made to write a file that exceeds the host specific maximum file size allowed.

`ENOSPC`
:   No space on device to write the data.

`EINTR`
:   The call was interrupted by the user.

#### [lseek](about:blank/gdb_toc.html#TOC324)

```
Synopsis:
long lseek (int fd, long offset, int flag);

Request:
Flseek,fd,offset,flag

```

`flag` is one of:

`SEEK_SET`
:   The offset is set to offset bytes.

`SEEK_CUR`
:   The offset is set to its current location plus offset bytes.

`SEEK_END`
:   The offset is set to the size of the file plus offset bytes.

```
Return value:
On success, the resulting unsigned offset in bytes from
the beginning of the file is returned.  Otherwise, a
value of -1 is returned.

Errors:

```

`EBADF`
:   fd is not a valid open file descriptor.

`ESPIPE`
:   fd is associated with the GDB console.

`EINVAL`
:   flag is not a proper value.

`EINTR`
:   The call was interrupted by the user.

#### [rename](about:blank/gdb_toc.html#TOC325)

```
Synopsis:
int rename(const char *oldpath, const char *newpath);

Request:
Frename,oldpathptr/len,newpathptr/len

Return value:
On success, zero is returned.  On error, -1 is returned.

Errors:

```

`EISDIR`
:   newpath is an existing directory, but oldpath is not a directory.

`EEXIST`
:   newpath is a non-empty directory.

`EBUSY`
:   oldpath or newpath is a directory that is in use by some process.

`EINVAL`
:   An attempt was made to make a directory a subdirectory of itself.

`ENOTDIR`
:   A component used as a directory in oldpath or new path is not a directory. Or oldpath is a directory and newpath exists but is not a directory.

`EFAULT`
:   oldpathptr or newpathptr are invalid pointer values.

`EACCES`
:   No access to the file or the path of the file.

`ENAMETOOLONG`
:   oldpath or newpath was too long.

`ENOENT`
:   A directory component in oldpath or newpath does not exist.

`EROFS`
:   The file is on a read-only filesystem.

`ENOSPC`
:   The device containing the file has no room for the new directory entry.

`EINTR`
:   The call was interrupted by the user.

#### [unlink](about:blank/gdb_toc.html#TOC326)

```
Synopsis:
int unlink(const char *pathname);

Request:
Funlink,pathnameptr/len

Return value:
On success, zero is returned.  On error, -1 is returned.

Errors:

```

`EACCES`
:   No access to the file or the path of the file.

`EPERM`
:   The system does not allow unlinking of directories.

`EBUSY`
:   The file pathname cannot be unlinked because it's being used by another process.

`EFAULT`
:   pathnameptr is an invalid pointer value.

`ENAMETOOLONG`
:   pathname was too long.

`ENOENT`
:   A directory component in pathname does not exist.

`ENOTDIR`
:   A component of the path is not a directory.

`EROFS`
:   The file is on a read-only filesystem.

`EINTR`
:   The call was interrupted by the user.

#### [stat/fstat](about:blank/gdb_toc.html#TOC327)

```
Synopsis:
int stat(const char *pathname, struct stat *buf);
int fstat(int fd, struct stat *buf);

Request:
Fstat,pathnameptr/len,bufptr
Ffstat,fd,bufptr

Return value:
On success, zero is returned.  On error, -1 is returned.

Errors:

```

`EBADF`
:   fd is not a valid open file.

`ENOENT`
:   A directory component in pathname does not exist or the path is an empty string.

`ENOTDIR`
:   A component of the path is not a directory.

`EFAULT`
:   pathnameptr is an invalid pointer value.

`EACCES`
:   No access to the file or the path of the file.

`ENAMETOOLONG`
:   pathname was too long.

`EINTR`
:   The call was interrupted by the user.

#### [gettimeofday](about:blank/gdb_toc.html#TOC328)

```
Synopsis:
int gettimeofday(struct timeval *tv, void *tz);

Request:
Fgettimeofday,tvptr,tzptr

Return value:
On success, 0 is returned, -1 otherwise.

Errors:

```

`EINVAL`
:   tz is a non-NULL pointer.

`EFAULT`
:   tvptr and/or tzptr is an invalid pointer value.

#### [isatty](about:blank/gdb_toc.html#TOC329)

```
Synopsis:
int isatty(int fd);

Request:
Fisatty,fd

Return value:
Returns 1 if fd refers to the GDB console, 0 otherwise.

Errors:

```

`EINTR`
:   The call was interrupted by the user.

#### [system](about:blank/gdb_toc.html#TOC330)

```
Synopsis:
int system(const char *command);

Request:
Fsystem,commandptr/len

Return value:
The value returned is -1 on error and the return status
of the command otherwise.  Only the exit status of the
command is returned, which is extracted from the hosts
system return value by calling WEXITSTATUS(retval).
In case /bin/sh could not be executed, 127 is returned.

Errors:

```

`EINTR`
:   The call was interrupted by the user.

### [Protocol specific representation of datatypes](about:blank/gdb_toc.html#TOC331)

#### [Integral datatypes](about:blank/gdb_toc.html#TOC332)

The integral datatypes used in the system calls are

```
int, unsigned int, long, unsigned long, mode_t and time_t

```

`Int`, `unsigned int`, `mode_t` and `time_t` are implemented as 32 bit values in
this protocol.

`Long` and `unsigned long` are implemented as 64 bit types.

See section [Limits](about:blank/gdb_33.html#SEC341), for corresponding MIN and
MAX values (similar to those in `limits.h') to allow range checking on host and
target.

`time_t` datatypes are defined as seconds since the Epoch.

All integral datatypes transferred as part of a memory read or write of a
structured datatype e.g. a `struct stat` have to be given in big endian byte
order.

#### [Pointer values](about:blank/gdb_toc.html#TOC333)

Pointers to target data are transmitted as they are. An exception is made for
pointers to buffers for which the length isn't transmitted as part of the
function call, namely strings. Strings are transmitted as a pointer/length pair,
both as hex values, e.g.

```
1aaf/12

```

which is a pointer to data of length 18 bytes at position 0x1aaf. The length is
defined as the full string length in bytes, including the trailing null byte.
Example:

```
"hello, world" at address 0x123456

```

is transmitted as

```
123456/d

```

#### [struct stat](about:blank/gdb_toc.html#TOC334)

The buffer of type struct stat used by the target and GDB is defined as follows:

```
struct stat {
    unsigned int  st_dev;      /* device */
    unsigned int  st_ino;      /* inode */
    mode_t        st_mode;     /* protection */
    unsigned int  st_nlink;    /* number of hard links */
    unsigned int  st_uid;      /* user ID of owner */
    unsigned int  st_gid;      /* group ID of owner */
    unsigned int  st_rdev;     /* device type (if inode device) */
    unsigned long st_size;     /* total size, in bytes */
    unsigned long st_blksize;  /* blocksize for filesystem I/O */
    unsigned long st_blocks;   /* number of blocks allocated */
    time_t        st_atime;    /* time of last access */
    time_t        st_mtime;    /* time of last modification */
    time_t        st_ctime;    /* time of last change */
};

```

The integral datatypes are conforming to the definitions given in the approriate
section (see section [Integral datatypes](about:blank/gdb_33.html#SEC332), for
details) so this structure is of size 64 bytes.

The values of several fields have a restricted meaning and/or range of values.

```
st_dev:     0       file
            1       console

st_ino:     No valid meaning for the target.  Transmitted unchanged.

st_mode:    Valid mode bits are described in Appendix C.  Any other
            bits have currently no meaning for the target.

st_uid:     No valid meaning for the target.  Transmitted unchanged.

st_gid:     No valid meaning for the target.  Transmitted unchanged.

st_rdev:    No valid meaning for the target.  Transmitted unchanged.

st_atime, st_mtime, st_ctime:
            These values have a host and file system dependent
            accuracy.  Especially on Windows hosts the file systems
            don't support exact timing values.

```

The target gets a struct stat of the above representation and is responsible to
coerce it to the target representation before continuing.

Note that due to size differences between the host and target representation of
stat members, these members could eventually get truncated on the target.

#### [struct timeval](about:blank/gdb_toc.html#TOC335)

The buffer of type struct timeval used by the target and GDB is defined as
follows:

```
struct timeval {
    time_t tv_sec;  /* second */
    long   tv_usec; /* microsecond */
};

```

The integral datatypes are conforming to the definitions given in the approriate
section (see section [Integral datatypes](about:blank/gdb_33.html#SEC332), for
details) so this structure is of size 8 bytes.

### [Constants](about:blank/gdb_toc.html#TOC336)

The following values are used for the constants inside of the protocol. GDB and
target are resposible to translate these values before and after the call as
needed.

#### [Open flags](about:blank/gdb_toc.html#TOC337)

All values are given in hexadecimal representation.

```
  O_RDONLY        0x0
  O_WRONLY        0x1
  O_RDWR          0x2
  O_APPEND        0x8
  O_CREAT       0x200
  O_TRUNC       0x400
  O_EXCL        0x800

```

#### [mode_t values](about:blank/gdb_toc.html#TOC338)

All values are given in octal representation.

```
  S_IFREG       0100000
  S_IFDIR        040000
  S_IRUSR          0400
  S_IWUSR          0200
  S_IXUSR          0100
  S_IRGRP           040
  S_IWGRP           020
  S_IXGRP           010
  S_IROTH            04
  S_IWOTH            02
  S_IXOTH            01

```

#### [Errno values](about:blank/gdb_toc.html#TOC339)

All values are given in decimal representation.

```
  EPERM           1
  ENOENT          2
  EINTR           4
  EBADF           9
  EACCES         13
  EFAULT         14
  EBUSY          16
  EEXIST         17
  ENODEV         19
  ENOTDIR        20
  EISDIR         21
  EINVAL         22
  ENFILE         23
  EMFILE         24
  EFBIG          27
  ENOSPC         28
  ESPIPE         29
  EROFS          30
  ENAMETOOLONG   91
  EUNKNOWN       9999

```

EUNKNOWN is used as a fallback error value if a host system returns any error
value not in the list of supported error numbers.

#### [Lseek flags](about:blank/gdb_toc.html#TOC340)

```
  SEEK_SET      0
  SEEK_CUR      1
  SEEK_END      2

```

#### [Limits](about:blank/gdb_toc.html#TOC341)

All values are given in decimal representation.

```
  INT_MIN       -2147483648
  INT_MAX        2147483647
  UINT_MAX       4294967295
  LONG_MIN      -9223372036854775808
  LONG_MAX       9223372036854775807
  ULONG_MAX      18446744073709551615

```

### [File-I/O Examples](about:blank/gdb_toc.html#TOC342)

Example sequence of a write call, file descriptor 3, buffer is at target address
0x1234, 6 bytes should be written:

```
<- Fwrite,3,1234,6
request memory read from target
-> m1234,6
<- XXXXXX
return "6 bytes written"
-> F6

```

Example sequence of a read call, file descriptor 3, buffer is at target address
0x1234, 6 bytes should be read:

```
<- Fread,3,1234,6
request memory write to target
-> X1234,6:XXXXXX
return "6 bytes read"
-> F6

```

Example sequence of a read call, call fails on the host due to invalid file
descriptor (EBADF):

```
<- Fread,3,1234,6
-> F-1,9

```

Example sequence of a read call, user presses Ctrl-C before syscall on host is
called:

```
<- Fread,3,1234,6
-> F-1,4,C
<- T02

```

Example sequence of a read call, user presses Ctrl-C after syscall on host is
called:

```
<- Fread,3,1234,6
-> X1234,6:XXXXXX
<- T02

```

---

Go to the [first](gdb_1.html), [previous](gdb_32.html), [next](gdb_34.html),
[last](gdb_36.html) section, [table of contents](gdb_toc.html).