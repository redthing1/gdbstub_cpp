# Packets (Debugging with GDB)

The following table provides a complete list of all currently defined commands
and their corresponding response data. See [File-I/O Remote Protocol
Extension](about:blank/File_002dI_002fO-Remote-Protocol-Extension.html#File_002dI_002fO-Remote-Protocol-Extension),
for details about the File I/O extension of the remote protocol.

Each packet’s description has a template showing the packet’s overall syntax,
followed by an explanation of the packet’s meaning. We include spaces in some of
the templates for clarity; these are not part of the packet’s syntax. No GDB
packet uses spaces to separate its components. For example, a template like
‘`foo bar baz`’ describes a packet beginning with the three ASCII bytes ‘`foo`’,
followed by a bar, followed directly by a baz. GDB does not transmit a space
character between the ‘`foo`’ and the bar, or between the bar and the baz.

Several packets and replies include a thread-id field to identify a thread.
Normally these are positive numbers with a target-specific interpretation,
formatted as big-endian hex strings. A thread-id can also be a literal ‘`-1`’ to
indicate all threads, or ‘`0`’ to pick any thread.

In addition, the remote protocol supports a multiprocess feature in which the
thread-id syntax is extended to optionally include both process and thread ID
fields, as ‘`ppid.tid`’. The pid (process) and tid (thread) components each have
the format described above: a positive number with target-specific
interpretation formatted as a big-endian hex string, literal ‘`-1`’ to indicate
all processes or threads (respectively), or ‘`0`’ to indicate an arbitrary
process or thread. Specifying just a process, as ‘`ppid`’, is equivalent to
‘`ppid.-1`’. It is an error to specify all processes but a specific thread, such
as ‘`p-1.tid`’. Note that the ‘`p`’ prefix is *not* used for those packets and
replies explicitly documented to include a process ID, rather than a thread-id.

The multiprocess thread-id syntax extensions are only used if both GDB and the
stub report support for the ‘`multiprocess`’ feature using ‘`qSupported`’. See
[multiprocess
extensions](about:blank/General-Query-Packets.html#multiprocess-extensions), for
more information.

Note that all packet forms beginning with an upper- or lower-case letter, other
than those described here, are reserved for future use.

Here are the packet descriptions.

‘`!`’
:   Enable extended mode. In extended mode, the remote server is made persistent.
    The ‘`R`’ packet is used to restart the program being debugged.

    Reply:

    ‘`OK`’
    :   The remote target both supports and has enabled extended mode.

‘`?`’
:   This is sent when connection is first established to query the reason the target
    halted. The reply is the same as for step and continue. This packet has a
    special interpretation when the target is in non-stop mode; see [Remote
    Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`A arglen,argnum,arg,...`’
:   Initialized `argv[]` array passed into program. arglen specifies the number of
    bytes in the hex encoded byte stream arg. See `gdbserver` for more details.

    Reply:

    ‘`OK`’
    :   The arguments were set.

‘`b baud`’
:   (Don’t use this packet; its behavior is not well-defined.) Change the serial
    line speed to baud.

    JTC: *When does the transport layer state change? When it’s received, or after
    the ACK is transmitted. In either case, there are problems if the command or the
    acknowledgment packet is dropped.*

    Stan: *If people really wanted to add something like this, and get it working
    for the first time, they ought to modify ser-unix.c to send some kind of
    out-of-band message to a specially-setup stub and have the switch happen "in
    between" packets, so that from remote protocol’s point of view, nothing actually
    happened.*

‘`B addr,mode`’
:   Set (mode is ‘`S`’) or clear (mode is ‘`C`’) a breakpoint at addr.

    Don’t use this packet. Use the ‘`Z`’ and ‘`z`’ packets instead (see [insert
    breakpoint or watchpoint packet](#insert-breakpoint-or-watchpoint-packet)).

‘`bc`’
:   Backward continue. Execute the target system in reverse. No parameter. See
    [Reverse Execution](about:blank/Reverse-Execution.html#Reverse-Execution), for
    more information.

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`bs`’
:   Backward single step. Execute one instruction in reverse. No parameter. See
    [Reverse Execution](about:blank/Reverse-Execution.html#Reverse-Execution), for
    more information.

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`c [addr]`’
:   Continue at addr, which is the address to resume. If addr is omitted, resume at
    current address.

    This packet is deprecated for multi-threading support. See [vCont
    packet](#vCont-packet).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`C sig[;addr]`’
:   Continue with signal sig (hex signal number). If ‘`;addr`’ is omitted, resume at
    same address.

    This packet is deprecated for multi-threading support. See [vCont
    packet](#vCont-packet).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`d`’
:   Toggle debug flag.

    Don’t use this packet; instead, define a general set packet (see [General Query
    Packets](about:blank/General-Query-Packets.html#General-Query-Packets)).

‘`D`’

‘`D;pid`’
:   The first form of the packet is used to detach GDB from the remote system. It is
    sent to the remote target before GDB disconnects via the `detach` command.

    The second form, including a process ID, is used when multiprocess protocol
    extensions are enabled (see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions)), to
    detach only a specific process. The pid is specified as a big-endian hex string.

    Reply:

    ‘`OK`’
    :   for success

‘`F RC,EE,CF;XX`’
:   A reply from GDB to an ‘`F`’ packet sent by the target. This is part of the
    File-I/O protocol extension. See [File-I/O Remote Protocol
    Extension](about:blank/File_002dI_002fO-Remote-Protocol-Extension.html#File_002dI_002fO-Remote-Protocol-Extension),
    for the specification.

‘`g`’
:   Read general registers.

    Reply:

    ‘`XX...`’
    :   Each byte of register data is described by two hex digits. The bytes with the
        register are transmitted in target byte order. The size of each register and
        their position within the ‘`g`’ packet are determined by the target description
        (see [Target
        Descriptions](about:blank/Target-Descriptions.html#Target-Descriptions)); in the
        absence of a target description, this is done using code internal to GDB;
        typically this is some customary register layout for the architecture in
        question.

        When reading registers, the stub may also return a string of literal ‘`x`’’s in
        place of the register data digits, to indicate that the corresponding register’s
        value is unavailable. For example, when reading registers from a trace frame
        (see [Using the Collected
        Data](about:blank/Analyze-Collected-Data.html#Analyze-Collected-Data)), this
        means that the register has not been collected in the trace frame. When reading
        registers from a live program, this indicates that the stub has no means to
        access the register contents, even though the corresponding register is known to
        exist. Note that if a register truly does not exist on the target, then it is
        better to not include it in the target description in the first place.

        For example, for an architecture with 4 registers of 4 bytes each, the following
        reply indicates to GDB that registers 0 and 2 are unavailable, while registers 1
        and 3 are available, and both have zero value:

        ```
        -> g
        <- xxxxxxxx00000000xxxxxxxx00000000
        ```

‘`G XX...`’
:   Write general registers. See [read registers packet](#read-registers-packet),
    for a description of the XX... data.

    Reply:

    ‘`OK`’
    :   for success

‘`H op thread-id`’
:   Set thread for subsequent operations (‘`m`’, ‘`M`’, ‘`g`’, ‘`G`’, et.al.).
    Depending on the operation to be performed, op should be ‘`c`’ for step and
    continue operations (note that this is deprecated, supporting the ‘`vCont`’
    command is a better option), and ‘`g`’ for other operations. The thread
    designator thread-id has the format and interpretation described in [thread-id
    syntax](#thread_002did-syntax).

    Reply:

    ‘`OK`’
    :   for success

‘`i [addr[,nnn]]`’
:   Step the remote target by a single clock cycle. If ‘`,nnn`’ is present, cycle
    step nnn cycles. If addr is present, cycle step starting at that address.

‘`I`’
:   Signal, then cycle step. See [step with signal
    packet](#step-with-signal-packet). See [cycle step packet](#cycle-step-packet).

‘`k`’
:   Kill request.

    The exact effect of this packet is not specified.

    For a bare-metal target, it may power cycle or reset the target system. For that
    reason, the ‘`k`’ packet has no reply.

    For a single-process target, it may kill that process if possible.

    A multiple-process target may choose to kill just one process, or all that are
    under GDB’s control. For more precise control, use the vKill packet (see [vKill
    packet](#vKill-packet)).

    If the target system immediately closes the connection in response to ‘`k`’, GDB
    does not consider the lack of packet acknowledgment to be an error, and assumes
    the kill was successful.

    If connected using `target extended-remote`, and the target does not close the
    connection in response to a kill request, GDB probes the target state as if a
    new connection was opened (see [? packet](#g_t_003f-packet)).

‘`m addr,length`’
:   Read length addressable memory units starting at address addr (see [addressable
    memory unit](about:blank/Memory.html#addressable-memory-unit)). Note that addr
    does not have to be aligned to any particular boundary.

    The stub need not use any particular size or alignment when gathering data from
    memory for the response; even if addr is word-aligned and length is a multiple
    of the word size, the stub is free to use byte accesses, or not. For this
    reason, this packet may not be suitable for accessing memory-mapped I/O devices.

    Reply:

    ‘`XX...`’
    :   Memory contents; each byte is transmitted as a two-digit hexadecimal number. The
        reply may contain fewer addressable memory units than requested if the server
        was reading from a trace frame memory and was able to read only part of the
        region of memory.

    Unlike most packets, this packet does not support ‘`E.errtext`’-style textual
    error replies (see [textual error
    reply](about:blank/Standard-Replies.html#textual-error-reply)) by default. Stubs
    should be careful to only send such a reply if GDB reported support for it with
    the `error-message` feature (see
    [error-message](about:blank/General-Query-Packets.html#error_002dmessage)).

‘`M addr,length:XX...`’
:   Write length addressable memory units starting at address addr (see [addressable
    memory unit](about:blank/Memory.html#addressable-memory-unit)). The data is
    given by XX...; each byte is transmitted as a two-digit hexadecimal number.

    Reply:

    ‘`OK`’
    :   All the data was written successfully. (If only part of the data was written,
        this command returns an error.)

‘`p n`’
:   Read the value of register n; n is in hex. See [read registers
    packet](#read-registers-packet), for a description of how the returned register
    value is encoded.

    Reply:

    ‘`XX...`’
    :   the register’s value

‘`P n...=r...`’
:   Write register n... with value r.... The register number n is in hexadecimal, and r...
    contains two hex digits for each byte in the register (target byte order).

    Reply:

    ‘`OK`’
    :   for success

‘`q name params...`’

‘`Q name params...`’
:   General query (‘`q`’) and set (‘`Q`’). These packets are described fully in
    [General Query
    Packets](about:blank/General-Query-Packets.html#General-Query-Packets).

‘`r`’
:   Reset the entire system.

    Don’t use this packet; use the ‘`R`’ packet instead.

‘`R XX`’
:   Restart the program being debugged. The XX, while needed, is ignored. This
    packet is only available in extended mode (see [extended mode](#extended-mode)).

    The ‘`R`’ packet has no reply.

‘`s [addr]`’
:   Single step, resuming at addr. If addr is omitted, resume at same address.

    This packet is deprecated for multi-threading support. See [vCont
    packet](#vCont-packet).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`S sig[;addr]`’
:   Step with signal. This is analogous to the ‘`C`’ packet, but requests a
    single-step, rather than a normal resumption of execution.

    This packet is deprecated for multi-threading support. See [vCont
    packet](#vCont-packet).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`t addr:PP,MM`’
:   Search backwards starting at address addr for a match with pattern PP and mask
    MM, both of which are are 4 byte long. There must be at least 3 digits in addr.

‘`T thread-id`’
:   Find out if the thread thread-id is alive. See [thread-id
    syntax](#thread_002did-syntax).

    Reply:

    ‘`OK`’
    :   thread is still alive

‘`v`’
:   Packets starting with ‘`v`’ are identified by a multi-letter name, up to the
    first ‘`;`’ or ‘`?`’ (or the end of the packet).

‘`vAttach;pid`’
:   Attach to a new process with the specified process ID pid. The process ID is a
    hexadecimal integer identifying the process. In all-stop mode, all threads in
    the attached process are stopped; in non-stop mode, it may be attached without
    being stopped if that is supported by the target.

    This packet is only available in extended mode (see [extended
    mode](#extended-mode)).

    Reply:

    ‘`Any stop packet`’
    :   for success in all-stop mode (see [Stop Reply
        Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets))

    ‘`OK`’
    :   for success in non-stop mode (see [Remote
        Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop))

‘`vCont[;action[:thread-id]]...`’
:   Resume the inferior, specifying different actions for each thread.

    For each inferior thread, the leftmost action with a matching thread-id is
    applied. Threads that don’t match any action remain in their current state.
    Thread IDs are specified using the syntax described in [thread-id
    syntax](#thread_002did-syntax). If multiprocess extensions (see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions)) are
    supported, actions can be specified to match all threads in a process by using
    the ‘`ppid.-1`’ form of the thread-id. An action with no thread-id matches all
    threads. Specifying no actions is an error.

    Currently supported actions are:

    ‘`c`’
    :   Continue.

    ‘`C sig`’
    :   Continue with signal sig. The signal sig should be two hex digits.

    ‘`s`’
    :   Step.

    ‘`S sig`’
    :   Step with signal sig. The signal sig should be two hex digits.

    ‘`t`’
    :   Stop.

    ‘`r start,end`’
    :   Step once, and then keep stepping as long as the thread stops at addresses
        between start (inclusive) and end (exclusive). The remote stub reports a stop
        reply when either the thread goes out of the range or is stopped due to an
        unrelated reason, such as hitting a breakpoint. See [range
        stepping](about:blank/Continuing-and-Stepping.html#range-stepping).

        If the range is empty (start == end), then the action becomes equivalent to the
        ‘`s`’ action. In other words, single-step once, and report the stop (even if the
        stepped instruction jumps to start).

        (A stop reply may be sent at any point even if the PC is still within the
        stepping range; for example, it is valid to implement this packet in a
        degenerate way as a single instruction step operation.)

    The optional argument addr normally associated with the ‘`c`’, ‘`C`’, ‘`s`’, and
    ‘`S`’ packets is not supported in ‘`vCont`’.

    The ‘`t`’ action is only relevant in non-stop mode (see [Remote
    Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop)) and may be
    ignored by the stub otherwise. A stop reply should be generated for any affected
    thread not already stopped. When a thread is stopped by means of a ‘`t`’ action,
    the corresponding stop reply should indicate that the thread has stopped with
    signal ‘`0`’, regardless of whether the target uses some other signal as an
    implementation detail.

    The server must ignore ‘`c`’, ‘`C`’, ‘`s`’, ‘`S`’, and ‘`r`’ actions for threads
    that are already running. Conversely, the server must ignore ‘`t`’ actions for
    threads that are already stopped.

    *Note:* In non-stop mode, a thread is considered running until GDB acknowledges
    an asynchronous stop notification for it with the ‘`vStopped`’ packet (see
    [Remote Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop)).

    The stub must support ‘`vCont`’ if it reports support for multiprocess
    extensions (see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions)).

    Reply: See [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets), for the reply
    specifications.

‘`vCont?`’
:   Request a list of actions supported by the ‘`vCont`’ packet.

    Reply:

    ‘`vCont[;action...]`’
    :   The ‘`vCont`’ packet is supported. Each action is a supported command in the
        ‘`vCont`’ packet.

‘`vCtrlC`’
:   Interrupt remote target as if a control-C was pressed on the remote terminal.
    This is the equivalent to reacting to the `^C` (‘`\003`’, the control-C
    character) character in all-stop mode while the target is running, except this
    works in non-stop mode. See [interrupting remote
    targets](about:blank/Interrupts.html#interrupting-remote-targets), for more info
    on the all-stop variant.

    Reply:

    ‘`OK`’
    :   for success

‘`vFile:operation:parameter...`’
:   Perform a file operation on the target system. For details, see [Host I/O
    Packets](about:blank/Host-I_002fO-Packets.html#Host-I_002fO-Packets).

‘`vFlashErase:addr,length`’
:   Direct the stub to erase length bytes of flash starting at addr. The region may
    enclose any number of flash blocks, but its start and end must fall on block
    boundaries, as indicated by the flash block size appearing in the memory map
    (see [Memory Map Format](about:blank/Memory-Map-Format.html#Memory-Map-Format)).
    GDB groups flash memory programming operations together, and sends a
    ‘`vFlashDone`’ request after each group; the stub is allowed to delay erase
    operation until the ‘`vFlashDone`’ packet is received.

    Reply:

    ‘`OK`’
    :   for success

‘`vFlashWrite:addr:XX...`’
:   Direct the stub to write data to flash address addr. The data is passed in
    binary form using the same encoding as for the ‘`X`’ packet (see [Binary
    Data](about:blank/Overview.html#Binary-Data)). The memory ranges specified by
    ‘`vFlashWrite`’ packets preceding a ‘`vFlashDone`’ packet must not overlap, and
    must appear in order of increasing addresses (although ‘`vFlashErase`’ packets
    for higher addresses may already have been received; the ordering is guaranteed
    only between ‘`vFlashWrite`’ packets). If a packet writes to an address that was
    neither erased by a preceding ‘`vFlashErase`’ packet nor by some other
    target-specific method, the results are unpredictable.

    Reply:

    ‘`OK`’
    :   for success

    ‘`E.memtype`’
    :   for vFlashWrite addressing non-flash memory

‘`vFlashDone`’
:   Indicate to the stub that flash programming operation is finished. The stub is
    permitted to delay or batch the effects of a group of ‘`vFlashErase`’ and
    ‘`vFlashWrite`’ packets until a ‘`vFlashDone`’ packet is received. The contents
    of the affected regions of flash memory are unpredictable until the
    ‘`vFlashDone`’ request is completed.

‘`vKill;pid`’
:   Kill the process with the specified process ID pid, which is a hexadecimal
    integer identifying the process. This packet is used in preference to ‘`k`’ when
    multiprocess protocol extensions are supported; see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions).

    Reply:

    ‘`OK`’
    :   for success

‘`vMustReplyEmpty`’
:   The correct reply to an unknown ‘`v`’ packet is to return the empty string,
    however, some older versions of `gdbserver` would incorrectly return ‘`OK`’ for
    unknown ‘`v`’ packets.

    The ‘`vMustReplyEmpty`’ is used as a feature test to check how `gdbserver`
    handles unknown packets, it is important that this packet be handled in the same
    way as other unknown ‘`v`’ packets. If this packet is handled differently to
    other unknown ‘`v`’ packets then it is possible that GDB may run into problems
    in other areas, specifically around use of ‘`vFile:setfs:`’.

‘`vRun;filename[;argument]...`’
:   Run the program filename, passing it each argument on its command line. The file
    and arguments are hex-encoded strings. If filename is an empty string, the stub
    may use a default program (e.g. the last program run). The program is created in
    the stopped state.

    If GDB sent the ‘`single-inf-arg`’ feature in the ‘`qSupported`’ packet (see
    [single-inf-arg](about:blank/General-Query-Packets.html#single_002dinf_002darg)),
    and the stub replied with ‘`single-inf-arg+`’, then there will only be a single
    argument string, which includes all inferior arguments, separated with
    whitespace.

    This packet is only available in extended mode (see [extended
    mode](#extended-mode)).

    Reply:

    ‘`Any stop packet`’
    :   for success (see [Stop Reply
        Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets))

‘`vStopped`’
:   See [Notification
    Packets](about:blank/Notification-Packets.html#Notification-Packets).

‘`x addr,length`’
:   Read length addressable memory units starting at address addr (see [addressable
    memory unit](about:blank/Memory.html#addressable-memory-unit)). Note that addr
    does not have to be aligned to any particular boundary.

    The stub need not use any particular size or alignment when gathering data from
    memory for the response; even if addr is word-aligned and length is a multiple
    of the word size, the stub is free to use byte accesses, or not. For this
    reason, this packet may not be suitable for accessing memory-mapped I/O devices.

    GDB will only use this packet if the stub reports the ‘`binary-upload`’ feature
    is supported in its ‘`qSupported`’ reply (see
    [qSupported](about:blank/General-Query-Packets.html#qSupported)).

    Reply:

    ‘`b XX...`’
    :   Memory contents as binary data (see [Binary
        Data](about:blank/Overview.html#Binary-Data)). The reply may contain fewer
        addressable memory units than requested if the server was reading from a trace
        frame memory and was able to read only part of the region of memory.

    ‘`E NN`’
    :   for an error

‘`X addr,length:XX...`’
:   Write data to memory, where the data is transmitted in binary. Memory is
    specified by its address addr and number of addressable memory units length (see
    [addressable memory unit](about:blank/Memory.html#addressable-memory-unit));
    ‘`XX...`’ is binary data (see [Binary
    Data](about:blank/Overview.html#Binary-Data)).

    Reply:

    ‘`OK`’
    :   for success

‘`z type,addr,kind`’

‘`Z type,addr,kind`’
:   Insert (‘`Z`’) or remove (‘`z`’) a type breakpoint or watchpoint starting at
    address address of kind kind.

    Each breakpoint and watchpoint packet type is documented separately.

    *Implementation notes: A remote target shall return an empty string for an
    unrecognized breakpoint or watchpoint packet type. A remote target shall support
    either both or neither of a given ‘`Ztype...`’ and ‘`ztype...`’ packet pair. To
    avoid potential problems with duplicate packets, the operations should be
    implemented in an idempotent way.*

‘`z0,addr,kind`’

‘`Z0,addr,kind[;cond_list...][;cmds:persist,cmd_list...]`’
:   Insert (‘`Z0`’) or remove (‘`z0`’) a software breakpoint at address addr of type
    kind.

    A software breakpoint is implemented by replacing the instruction at addr with a
    software breakpoint or trap instruction. The kind is target-specific and
    typically indicates the size of the breakpoint in bytes that should be inserted.
    E.g., the ARM and MIPS can insert either a 2 or 4 byte breakpoint. Some
    architectures have additional meanings for kind (see [Architecture-Specific
    Protocol
    Details](about:blank/Architecture_002dSpecific-Protocol-Details.html#Architecture_002dSpecific-Protocol-Details));
    if no architecture-specific value is being used, it should be ‘`0`’. kind is
    hex-encoded. cond_list is an optional list of conditional expressions in
    bytecode form that should be evaluated on the target’s side. These are the
    conditions that should be taken into consideration when deciding if the
    breakpoint trigger should be reported back to GDB.

    See also the ‘`swbreak`’ stop reason (see [swbreak stop
    reason](about:blank/Stop-Reply-Packets.html#swbreak-stop-reason)) for how to
    best report a software breakpoint event to GDB.

    The cond_list parameter is comprised of a series of expressions, concatenated
    without separators. Each expression has the following form:

    ‘`X len,expr`’
    :   len is the length of the bytecode expression and expr is the actual conditional
        expression in bytecode form.

    The optional cmd_list parameter introduces commands that may be run on the
    target, rather than being reported back to GDB. The parameter starts with a
    numeric flag persist; if the flag is nonzero, then the breakpoint may remain
    active and the commands continue to be run even when GDB disconnects from the
    target. Following this flag is a series of expressions concatenated with no
    separators. Each expression has the following form:

    ‘`X len,expr`’
    :   len is the length of the bytecode expression and expr is the actual commands
        expression in bytecode form.

    *Implementation note: It is possible for a target to copy or move code that
    contains software breakpoints (e.g., when implementing overlays). The behavior
    of this packet, in the presence of such a target, is not defined.*

    Reply:

    ‘`OK`’
    :   success

‘`z1,addr,kind`’

‘`Z1,addr,kind[;cond_list...][;cmds:persist,cmd_list...]`’
:   Insert (‘`Z1`’) or remove (‘`z1`’) a hardware breakpoint at address addr.

    A hardware breakpoint is implemented using a mechanism that is not dependent on
    being able to modify the target’s memory. The kind, cond_list, and cmd_list
    arguments have the same meaning as in ‘`Z0`’ packets.

    *Implementation note: A hardware breakpoint is not affected by code movement.*

    Reply:

    ‘`OK`’
    :   success

‘`z2,addr,kind`’

‘`Z2,addr,kind`’
:   Insert (‘`Z2`’) or remove (‘`z2`’) a write watchpoint at addr. The number of
    bytes to watch is specified by kind.

    Reply:

    ‘`OK`’
    :   success

‘`z3,addr,kind`’

‘`Z3,addr,kind`’
:   Insert (‘`Z3`’) or remove (‘`z3`’) a read watchpoint at addr. The number of
    bytes to watch is specified by kind.

    Reply:

    ‘`OK`’
    :   success

‘`z4,addr,kind`’

‘`Z4,addr,kind`’
:   Insert (‘`Z4`’) or remove (‘`z4`’) an access watchpoint at addr. The number of
    bytes to watch is specified by kind.

    Reply:

    ‘`OK`’
    :   success