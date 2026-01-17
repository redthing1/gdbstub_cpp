# General Query Packets (Debugging with GDB)

Packets starting with ‘`q`’ are *general query packets*; packets starting with
‘`Q`’ are *general set packets*. General query and set packets are a
semi-unified form for retrieving and sending information to and from the stub.

The initial letter of a query or set packet is followed by a name indicating
what sort of thing the packet applies to. For example, GDB may use a ‘`qSymbol`’
packet to exchange symbol definitions with the stub. These packet names follow
some conventions:

The name of a query or set packet should be separated from any parameters by a
‘`:`’; the parameters themselves should be separated by ‘`,`’ or ‘`;`’. Stubs
must be careful to match the full packet name, and check for a separator or the
end of the packet, in case two packet names share a common prefix. New packets
should not begin with ‘`qC`’, ‘`qP`’, or ‘`qL`’[21](#FOOT21).

Like the descriptions of the other packets, each description here has a template
showing the packet’s overall syntax, followed by an explanation of the packet’s
meaning. We include spaces in some of the templates for clarity; these are not
part of the packet’s syntax. No GDB packet uses spaces to separate its
components.

‘`QAgent:1`’

‘`QAgent:0`’
:   Turn on or off the agent as a helper to perform some debugging operations
    delegated from GDB (see [Control
    Agent](about:blank/In_002dProcess-Agent.html#Control-Agent)).

‘`QAllow:op:val...`’
:   Specify which operations GDB expects to request of the target, as a
    semicolon-separated list of operation name and value pairs. Possible values for
    op include ‘`WriteReg`’, ‘`WriteMem`’, ‘`InsertBreak`’, ‘`InsertTrace`’,
    ‘`InsertFastTrace`’, and ‘`Stop`’. val is either 0, indicating that GDB will not
    request the operation, or 1, indicating that it may. (The target can then use
    this to set up its own internals optimally, for instance if the debugger never
    expects to insert breakpoints, it may not need to install its own trap handler.)

‘`qC`’
:   Return the current thread ID.

    Reply:

    ‘`QC thread-id`’
    :   Where thread-id is a thread ID as documented in [thread-id
        syntax](about:blank/Packets.html#thread_002did-syntax).

    ‘`(anything else)`’
    :   Any other reply implies the old thread ID.

‘`qCRC:addr,length`’
:   Compute the CRC checksum of a block of memory using CRC-32 defined in IEEE
    802.3. The CRC is computed byte at a time, taking the most significant bit of
    each byte first. The initial pattern code `0xffffffff` is used to ensure leading
    zeros affect the CRC.

    *Note:* This is the same CRC used in validating separate debug files (see
    [Debugging Information in Separate
    Files](about:blank/Separate-Debug-Files.html#Separate-Debug-Files)). However the
    algorithm is slightly different. When validating separate debug files, the CRC
    is computed taking the *least* significant bit of each byte first, and the final
    result is inverted to detect trailing zeros.

    Reply:

    ‘`C crc32`’
    :   The specified memory region’s checksum is crc32.

‘`QDisableRandomization:value`’
:   Some target operating systems will randomize the virtual address space of the
    inferior process as a security feature, but provide a feature to disable such
    randomization, e.g. to allow for a more deterministic debugging experience. On
    such systems, this packet with a value of 1 directs the target to disable
    address space randomization for processes subsequently started via ‘`vRun`’
    packets, while a packet with a value of 0 tells the target to enable address
    space randomization.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). This should only be done on targets that actually
    support disabling address space randomization.

‘`QStartupWithShell:value`’
:   On UNIX-like targets, it is possible to start the inferior using a shell
    program. This is the default behavior on both GDB and `gdbserver` (see [set
    startup-with-shell](about:blank/Starting.html#set-startup_002dwith_002dshell)).
    This packet is used to inform `gdbserver` whether it should start the inferior
    using a shell or not.

    If value is ‘`0`’, `gdbserver` will not use a shell to start the inferior. If
    value is ‘`1`’, `gdbserver` will use a shell to start the inferior. All other
    values are considered an error.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). This should only be done on targets that actually
    support starting the inferior using a shell.

    Use of this packet is controlled by the `set startup-with-shell` command; see
    [set
    startup-with-shell](about:blank/Starting.html#set-startup_002dwith_002dshell).

‘`QEnvironmentHexEncoded:hex-value`’
:   On UNIX-like targets, it is possible to set environment variables that will be
    passed to the inferior during the startup process. This packet is used to inform
    `gdbserver` of an environment variable that has been defined by the user on GDB
    (see [set environment](about:blank/Environment.html#set-environment)).

    The packet is composed by hex-value, an hex encoded representation of the
    name=value format representing an environment variable. The name of the
    environment variable is represented by name, and the value to be assigned to the
    environment variable is represented by value. If the variable has no value
    (i.e., the value is `null`), then value will not be present.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). This should only be done on targets that actually
    support passing environment variables to the starting inferior.

    This packet is related to the `set environment` command; see [set
    environment](about:blank/Environment.html#set-environment).

‘`QEnvironmentUnset:hex-value`’
:   On UNIX-like targets, it is possible to unset environment variables before
    starting the inferior in the remote target. This packet is used to inform
    `gdbserver` of an environment variable that has been unset by the user on GDB
    (see [unset environment](about:blank/Environment.html#unset-environment)).

    The packet is composed by hex-value, an hex encoded representation of the name
    of the environment variable to be unset.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). This should only be done on targets that actually
    support passing environment variables to the starting inferior.

    This packet is related to the `unset environment` command; see [unset
    environment](about:blank/Environment.html#unset-environment).

‘`QEnvironmentReset`’
:   On UNIX-like targets, this packet is used to reset the state of environment
    variables in the remote target before starting the inferior. In this context,
    reset means unsetting all environment variables that were previously set by the
    user (i.e., were not initially present in the environment). It is sent to
    `gdbserver` before the ‘`QEnvironmentHexEncoded`’ (see
    [QEnvironmentHexEncoded](#QEnvironmentHexEncoded)) and the ‘`QEnvironmentUnset`’
    (see [QEnvironmentUnset](#QEnvironmentUnset)) packets.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). This should only be done on targets that actually
    support passing environment variables to the starting inferior.

‘`QSetWorkingDir:[directory]`’
:   This packet is used to inform the remote server of the intended current working
    directory for programs that are going to be executed.

    The packet is composed by directory, an hex encoded representation of the
    directory that the remote inferior will use as its current working directory. If
    directory is an empty string, the remote server should reset the inferior’s
    current working directory to its original, empty value.

    This packet is only available in extended mode (see [extended
    mode](about:blank/Packets.html#extended-mode)).

    Reply:

    ‘`OK`’
    :   The request succeeded.

‘`qfThreadInfo`’

‘`qsThreadInfo`’
:   Obtain a list of all active thread IDs from the target (OS). Since there may be
    too many active threads to fit into one reply packet, this query works
    iteratively: it may require more than one query/reply sequence to obtain the
    entire list of threads. The first query of the sequence will be the
    ‘`qfThreadInfo`’ query; subsequent queries in the sequence will be the
    ‘`qsThreadInfo`’ query.

    NOTE: This packet replaces the ‘`qL`’ query (see below).

    Reply:

    ‘`m thread-id`’
    :   A single thread ID

    ‘`m thread-id,thread-id...`’
    :   a comma-separated list of thread IDs

    ‘`l`’
    :   (lower case letter ‘`L`’) denotes end of list.

    In response to each query, the target will reply with a list of one or more
    thread IDs, separated by commas. GDB will respond to each reply with a request
    for more thread ids (using the ‘`qs`’ form of the query), until the target
    responds with ‘`l`’ (lower-case ell, for *last*). Refer to [thread-id
    syntax](about:blank/Packets.html#thread_002did-syntax), for the format of the
    thread-id fields.

    *Note: GDB will send the `qfThreadInfo` query during the initial connection with
    the remote target, and the very first thread ID mentioned in the reply will be
    stopped by GDB in a subsequent message. Therefore, the stub should ensure that
    the first thread ID in the `qfThreadInfo` reply is suitable for being stopped by
    GDB.*

‘`qGetTLSAddr:thread-id,offset,lm`’
:   Fetch the address associated with thread local storage specified by thread-id,
    offset, and lm.

    thread-id is the thread ID associated with the thread for which to fetch the TLS
    address. See [thread-id syntax](about:blank/Packets.html#thread_002did-syntax).

    offset is the (big endian, hex encoded) offset associated with the thread local
    variable. (This offset is obtained from the debug information associated with
    the variable.)

    lm is the (big endian, hex encoded) OS/ABI-specific encoding of the load module
    associated with the thread local storage. For example, a GNU/Linux system will
    pass the link map address of the shared object associated with the thread local
    storage under consideration. Other operating environments may choose to
    represent the load module differently, so the precise meaning of this parameter
    will vary.

    Reply:

    ‘`XX...`’
    :   Hex encoded (big endian) bytes representing the address of the thread local
        storage requested.

‘`qGetTIBAddr:thread-id`’
:   Fetch address of the Windows OS specific Thread Information Block.

    thread-id is the thread ID associated with the thread.

    Reply:

    ‘`XX...`’
    :   Hex encoded (big endian) bytes representing the linear address of the thread
        information block.

‘`qL startflag threadcount nextthread`’
:   Obtain thread information from RTOS. Where: startflag (one hex digit) is one to
    indicate the first query and zero to indicate a subsequent query; threadcount
    (two hex digits) is the maximum number of threads the response packet can
    contain; and nextthread (eight hex digits), for subsequent queries (startflag is
    zero), is returned in the response as argthread.

    Don’t use this packet; use the ‘`qfThreadInfo`’ query instead (see above).

    Reply:

    ‘`qM count done argthread thread...`’
    :   Where: count (two hex digits) is the number of threads being returned; done (one
        hex digit) is zero to indicate more threads and one indicates no further
        threads; argthreadid (eight hex digits) is nextthread from the request packet;
        thread... is a sequence of thread IDs, threadid (eight hex digits), from the
        target. See `remote.c:parse_threadlist_response()`.

‘`qMemTags:start address,length:type`’
:   Fetch memory tags of type type from the address range
    [start address, start address + length). The target is responsible for
    calculating how many tags will be returned, as this is architecture-specific.

    start address is the starting address of the memory range.

    length is the length, in bytes, of the memory range.

    type is the type of tag the request wants to fetch. The type is a signed
    integer.

    GDB will only send this packet if the stub has advertised support for memory
    tagging via ‘`qSupported`’.

    Reply:

    ‘`mxx...`’
    :   Hex encoded sequence of uninterpreted bytes, xx..., representing the tags found in
        the requested memory range.

‘`qIsAddressTagged:address`’
:   Check if address address is in a memory tagged region; if it is, it’s said to be
    *tagged*. The target is responsible for checking it, as this is
    architecture-specific.

    address is the address to be checked.

    Reply:

    :   Replies to this packet should all be in two hex digit format, as follows:

    ‘`‘01’`’
    :   Address address is tagged.

    ‘`‘00’`’
    :   Address address is not tagged.

‘`QMemTags:start address,length:type:tag bytes`’
:   Store memory tags of type type to the address range
    [start address, start address + length). The target is responsible for
    interpreting the type, the tag bytes and modifying the memory tag granules
    accordingly, given this is architecture-specific.

    The interpretation of how many tags (nt) should be written to how many memory
    tag granules (ng) is also architecture-specific. The behavior is
    implementation-specific, but the following is suggested.

    If the number of memory tags, nt, is greater than or equal to the number of
    memory tag granules, ng, only ng tags will be stored.

    If nt is less than ng, the behavior is that of a fill operation, and the tag
    bytes will be used as a pattern that will get repeated until ng tags are stored.

    start address is the starting address of the memory range. The address does not
    have any restriction on alignment or size.

    length is the length, in bytes, of the memory range.

    type is the type of tag the request wants to fetch. The type is a signed
    integer.

    tag bytes is a sequence of hex encoded uninterpreted bytes which will be
    interpreted by the target. Each pair of hex digits is interpreted as a single
    byte.

    GDB will only send this packet if the stub has advertised support for memory
    tagging via ‘`qSupported`’.

    Reply:

    ‘`OK`’
    :   The request was successful and the memory tag granules were modified
        accordingly.

‘`qOffsets`’
:   Get section offsets that the target used when relocating the downloaded image.

    Reply:

    ‘`Text=xxx;Data=yyy[;Bss=zzz]`’
    :   Relocate the `Text` section by xxx from its original address. Relocate the
        `Data` section by yyy from its original address. If the object file format
        provides segment information (e.g. ELF ‘`PT_LOAD`’ program headers), GDB will
        relocate entire segments by the supplied offsets.

        *Note: while a `Bss` offset may be included in the response, GDB ignores this
        and instead applies the `Data` offset to the `Bss` section.*

    ‘`TextSeg=xxx[;DataSeg=yyy]`’
    :   Relocate the first segment of the object file, which conventionally contains
        program code, to a starting address of xxx. If ‘`DataSeg`’ is specified,
        relocate the second segment, which conventionally contains modifiable data, to a
        starting address of yyy. GDB will report an error if the object file does not
        contain segment information, or does not contain at least as many segments as
        mentioned in the reply. Extra segments are kept at fixed offsets relative to the
        last relocated segment.

‘`qP mode thread-id`’
:   Returns information on thread-id. Where: mode is a hex encoded 32 bit mode;
    thread-id is a thread ID (see [thread-id
    syntax](about:blank/Packets.html#thread_002did-syntax)).

    Don’t use this packet; use the ‘`qThreadExtraInfo`’ query instead (see below).

    Reply: see `remote.c:remote_unpack_thread_info_response()`.

‘`QNonStop:1`’

‘`QNonStop:0`’
:   Enter non-stop (‘`QNonStop:1`’) or all-stop (‘`QNonStop:0`’) mode. See [Remote
    Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop), for more
    information.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)). Use of this packet is controlled by the `set
    non-stop` command; see [Non-Stop
    Mode](about:blank/Non_002dStop-Mode.html#Non_002dStop-Mode).

‘`QCatchSyscalls:1 [;sysno]...`’

‘`QCatchSyscalls:0`’
:   Enable (‘`QCatchSyscalls:1`’) or disable (‘`QCatchSyscalls:0`’) catching
    syscalls from the inferior process.

    For ‘`QCatchSyscalls:1`’, each listed syscall sysno (encoded in hex) should be
    reported to GDB. If no syscall sysno is listed, every system call should be
    reported.

    Note that if a syscall not in the list is reported, GDB will still filter the
    event according to its own list from all corresponding `catch syscall` commands.
    However, it is more efficient to only report the requested syscalls.

    Multiple ‘`QCatchSyscalls:1`’ packets do not combine; any earlier
    ‘`QCatchSyscalls:1`’ list is completely replaced by the new list.

    If the inferior process execs, the state of ‘`QCatchSyscalls`’ is kept for the
    new process too. On targets where exec may affect syscall numbers, for example
    with exec between 32 and 64-bit processes, the client should send a new packet
    with the new syscall list.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    Use of this packet is controlled by the `set remote catch-syscalls` command (see
    [set remote
    catch-syscalls](about:blank/Remote-Configuration.html#Remote-Configuration)).
    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)).

‘`QPassSignals: signal [;signal]...`’
:   Each listed signal should be passed directly to the inferior process. Signals
    are numbered identically to continue packets and stop replies (see [Stop Reply
    Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets)). Each signal
    list item should be strictly greater than the previous item. These signals do
    not need to stop the inferior, or be reported to GDB. All other signals should
    be reported to GDB. Multiple ‘`QPassSignals`’ packets do not combine; any
    earlier ‘`QPassSignals`’ list is completely replaced by the new list. This
    packet improves performance when using ‘`handle signal nostop noprint pass`’.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    Use of this packet is controlled by the `set remote pass-signals` command (see
    [set remote
    pass-signals](about:blank/Remote-Configuration.html#Remote-Configuration)). This
    packet is not probed by default; the remote stub must request it, by supplying
    an appropriate ‘`qSupported`’ response (see [qSupported](#qSupported)).

‘`QProgramSignals: signal [;signal]...`’
:   Each listed signal may be delivered to the inferior process. Others should be
    silently discarded.

    In some cases, the remote stub may need to decide whether to deliver a signal to
    the program or not without GDB involvement. One example of that is while
    detaching -- the program’s threads may have stopped for signals that haven’t yet
    had a chance of being reported to GDB, and so the remote stub can use the signal
    list specified by this packet to know whether to deliver or ignore those pending
    signals.

    This does not influence whether to deliver a signal as requested by a resumption
    packet (see [vCont packet](about:blank/Packets.html#vCont-packet)).

    Signals are numbered identically to continue packets and stop replies (see [Stop
    Reply Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets)). Each
    signal list item should be strictly greater than the previous item. Multiple
    ‘`QProgramSignals`’ packets do not combine; any earlier ‘`QProgramSignals`’ list
    is completely replaced by the new list.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    Use of this packet is controlled by the `set remote program-signals` command
    (see [set remote
    program-signals](about:blank/Remote-Configuration.html#Remote-Configuration)).
    This packet is not probed by default; the remote stub must request it, by
    supplying an appropriate ‘`qSupported`’ response (see
    [qSupported](#qSupported)).

‘`QThreadEvents:1`’

‘`QThreadEvents:0`’
:   Enable (‘`QThreadEvents:1`’) or disable (‘`QThreadEvents:0`’) reporting of
    thread create and exit events. See [thread create
    event](about:blank/Stop-Reply-Packets.html#thread-create-event), for the reply
    specifications. For example, this is used in non-stop mode when GDB stops a set
    of threads and synchronously waits for the their corresponding stop replies.
    Without exit events, if one of the threads exits, GDB would hang forever not
    knowing that it should no longer expect a stop for that same thread. GDB does
    not enable this feature unless the stub reports that it supports it by including
    ‘`QThreadEvents+`’ in its ‘`qSupported`’ reply.

    This packet always enables/disables event reporting for all threads of all
    processes under control of the remote stub. For per-thread control of optional
    event reporting, see the [QThreadOptions](#QThreadOptions) packet.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    Use of this packet is controlled by the `set remote thread-events` command (see
    [set remote
    thread-events](about:blank/Remote-Configuration.html#Remote-Configuration)).

‘`QThreadOptions[;options[:thread-id]]...`’
:   For each inferior thread, the last options in the list with a matching thread-id
    are applied. Any options previously set on a thread are discarded and replaced
    by the new options specified. Threads that do not match any thread-id retain
    their previously-set options. Thread IDs are specified using the syntax
    described in [thread-id syntax](about:blank/Packets.html#thread_002did-syntax).
    If multiprocess extensions (see [multiprocess
    extensions](#multiprocess-extensions)) are supported, options can be specified
    to apply to all threads of a process by using the ‘`ppid.-1`’ form of thread-id.
    Options with no thread-id apply to all threads. Specifying no options value is
    an error. Zero is a valid value.

    options is an hexadecimal integer specifying the enabled thread options, and is
    the bitwise `OR` of the following values. All values are given in hexadecimal
    representation.

    `GDB_THREAD_OPTION_CLONE (0x1)`
    :   Report thread clone events (see [thread clone
        event](about:blank/Stop-Reply-Packets.html#thread-clone-event)). This is only
        meaningful for targets that support clone events (e.g., GNU/Linux systems).

    `GDB_THREAD_OPTION_EXIT (0x2)`
    :   Report thread exit events (see [thread exit
        event](about:blank/Stop-Reply-Packets.html#thread-exit-event)).

    For example, GDB enables the `GDB_THREAD_OPTION_EXIT` and
    `GDB_THREAD_OPTION_CLONE` options when single-stepping a thread past a
    breakpoint, for the following reasons:

    - If the single-stepped thread exits (e.g., it executes a thread exit system call), enabling `GDB_THREAD_OPTION_EXIT` prevents GDB from waiting forever, not knowing that it should no longer expect a stop for that same thread, and blocking other threads from progressing.
    - If the single-stepped thread spawns a new clone child (i.e., it executes a clone system call), enabling `GDB_THREAD_OPTION_CLONE` halts the cloned thread before it executes any instructions, and thus prevents the following problematic situations:
      - - If the breakpoint is stepped-over in-line, the spawned thread would incorrectly run free while the breakpoint being stepped over is not inserted, and thus the cloned thread may potentially run past the breakpoint without stopping for it;
      - - If displaced (out-of-line) stepping is used, the cloned thread starts running at the out-of-line PC, leading to undefined behavior, usually crashing or corrupting data.

    New threads start with thread options cleared.

    GDB does not enable this feature unless the stub reports that it supports it by
    including ‘`QThreadOptions=supported_options`’ in its ‘`qSupported`’ reply.

    Reply:

    ‘`OK`’
    :   The request succeeded.

    Use of this packet is controlled by the `set remote thread-options` command (see
    [set remote
    thread-options](about:blank/Remote-Configuration.html#Remote-Configuration)).

‘`qRcmd,command`’
:   command (hex encoded) is passed to the local interpreter for execution. Invalid
    commands should be reported using the output string. Before the final result
    packet, the target may also respond with a number of intermediate ‘`Ooutput`’
    console output packets. *Implementors should note that providing access to a
    stubs’s interpreter may have security implications*.

    Reply:

    ‘`OK`’
    :   A command response with no output.

    ‘`OUTPUT`’
    :   A command response with the hex encoded output string OUTPUT.

    Unlike most packets, this packet does not support ‘`E.errtext`’-style textual
    error replies (see [textual error
    reply](about:blank/Standard-Replies.html#textual-error-reply)) by default. Stubs
    should be careful to only send such a reply if GDB reported support for it with
    the `error-message` feature (see [error-message](#error_002dmessage)).

    (Note that the `qRcmd` packet’s name is separated from the command by a ‘`,`’,
    not a ‘`:`’, contrary to the naming conventions above. Please don’t use this
    packet as a model for new packets.)

‘`qSearch:memory:address;length;search-pattern`’
:   Search length bytes at address for search-pattern. Both address and length are
    encoded in hex; search-pattern is a sequence of binary-encoded bytes (see
    [Binary Data](about:blank/Overview.html#Binary-Data)).

    Reply:

    ‘`0`’
    :   The pattern was not found.

    ‘`1,address`’
    :   The pattern was found at address.

‘`QStartNoAckMode`’
:   Request that the remote stub disable the normal ‘`+`’/‘`-`’ protocol
    acknowledgments (see [Packet
    Acknowledgment](about:blank/Packet-Acknowledgment.html#Packet-Acknowledgment)).

    Reply:

    ‘`OK`’
    :   The stub has switched to no-acknowledgment mode. GDB acknowledges this response,
        but neither the stub nor GDB shall send or expect further ‘`+`’/‘`-`’
        acknowledgments in the current connection.

‘`qSupported [:gdbfeature [;gdbfeature]... ]`’
:   Tell the remote stub about features supported by GDB, and query the stub for
    features it supports. This packet allows GDB and the remote stub to take
    advantage of each others’ features. ‘`qSupported`’ also consolidates multiple
    feature probes at startup, to improve GDB performance--a single larger packet
    performs better than multiple smaller probe packets on high-latency links. Some
    features may enable behavior which must not be on by default, e.g. because it
    would confuse older clients or stubs. Other features may describe packets which
    could be automatically probed for, but are not. These features must be reported
    before GDB will use them. This “default unsupported” behavior is not appropriate
    for all packets, but it helps to keep the initial connection time under control
    with new versions of GDB which support increasing numbers of packets.

    Reply:

    ‘`stubfeature [;stubfeature]...`’
    :   The stub supports or does not support each returned stubfeature, depending on
        the form of each stubfeature (see below for the possible forms).

    The allowed forms for each feature (either a gdbfeature in the ‘`qSupported`’
    packet, or a stubfeature in the response) are:

    ‘`name=value`’
    :   The remote protocol feature name is supported, and associated with the specified
        value. The format of value depends on the feature, but it must not include a
        semicolon.

    ‘`name+`’
    :   The remote protocol feature name is supported, and does not need an associated
        value.

    ‘`name-`’
    :   The remote protocol feature name is not supported.

    ‘`name?`’
    :   The remote protocol feature name may be supported, and GDB should auto-detect
        support in some other way when it is needed. This form will not be used for
        gdbfeature notifications, but may be used for stubfeature responses.

    Whenever the stub receives a ‘`qSupported`’ request, the supplied set of GDB
    features should override any previous request. This allows GDB to put the stub
    in a known state, even if the stub had previously been communicating with a
    different version of GDB.

    The following values of gdbfeature (for the packet sent by GDB) are defined:

    ‘`multiprocess`’
    :   This feature indicates whether GDB supports multiprocess extensions to the
        remote protocol. GDB does not use such extensions unless the stub also reports
        that it supports them by including ‘`multiprocess+`’ in its ‘`qSupported`’
        reply. See [multiprocess extensions](#multiprocess-extensions), for details.

    ‘`xmlRegisters`’
    :   This feature indicates that GDB supports the XML target description. If the stub
        sees ‘`xmlRegisters=`’ with target specific strings separated by a comma, it
        will report register description.

    ‘`qRelocInsn`’
    :   This feature indicates whether GDB supports the ‘`qRelocInsn`’ packet (see
        [Relocate instruction reply
        packet](about:blank/Tracepoint-Packets.html#Tracepoint-Packets)).

    ‘`swbreak`’
    :   This feature indicates whether GDB supports the swbreak stop reason in stop
        replies. See [swbreak stop
        reason](about:blank/Stop-Reply-Packets.html#swbreak-stop-reason), for details.

    ‘`hwbreak`’
    :   This feature indicates whether GDB supports the hwbreak stop reason in stop
        replies. See [swbreak stop
        reason](about:blank/Stop-Reply-Packets.html#swbreak-stop-reason), for details.

    ‘`fork-events`’
    :   This feature indicates whether GDB supports fork event extensions to the remote
        protocol. GDB does not use such extensions unless the stub also reports that it
        supports them by including ‘`fork-events+`’ in its ‘`qSupported`’ reply.

    ‘`vfork-events`’
    :   This feature indicates whether GDB supports vfork event extensions to the remote
        protocol. GDB does not use such extensions unless the stub also reports that it
        supports them by including ‘`vfork-events+`’ in its ‘`qSupported`’ reply.

    ‘`exec-events`’
    :   This feature indicates whether GDB supports exec event extensions to the remote
        protocol. GDB does not use such extensions unless the stub also reports that it
        supports them by including ‘`exec-events+`’ in its ‘`qSupported`’ reply.

    ‘`vContSupported`’
    :   This feature indicates whether GDB wants to know the supported actions in the
        reply to ‘`vCont?`’ packet.

    ‘`error-message`’
    :   This feature indicates whether GDB supports accepting a reply in ‘`E.errtext`’
        format (See [textual error
        reply](about:blank/Standard-Replies.html#textual-error-reply)) from the
        ‘`qRcmd`’ and ‘`m`’ packets. These packets, historically, didn’t support
        ‘`E.errtext`’, and older versions of GDB didn’t expect to see a reply in this
        format.

        New packets should be written to support ‘`E.errtext`’ regardless of this
        feature being true or not.

    ‘`single-inf-arg`’
    :   This feature indicates that GDB would like to send the inferior arguments as a
        single string within the ‘`vRun`’ packet. GDB will not send the arguments as a
        single string unless the stub also reports that it supports this behaviour by
        including ‘`single-inf-arg+`’ in its ‘`qSupported`’ reply.

    ‘`multi-wp-addr`’
    :   This features indicates that GDB supports receiving multiple watchpoint
        addresses in the ‘`T`’ stop reply packet (see [Stop Reply
        Packets](about:blank/Stop-Reply-Packets.html#Stop-Reply-Packets)).

        Use of this feature is controlled by the `set remote
        multiple-watchpoint-addresses-packet` command (see [set remote
        multiple-watchpoint-addresses-packet](about:blank/Remote-Configuration.html#Remote-Configuration)).

    Stubs should ignore any unknown values for gdbfeature. Any GDB which sends a
    ‘`qSupported`’ packet supports receiving packets of unlimited length (earlier
    versions of GDB may reject overly long responses). Additional values for
    gdbfeature may be defined in the future to let the stub take advantage of new
    features in GDB, e.g. incompatible improvements in the remote protocol--the
    ‘`multiprocess`’ feature is an example of such a feature. The stub’s reply
    should be independent of the gdbfeature entries sent by GDB; first GDB describes
    all the features it supports, and then the stub replies with all the features it
    supports.

    Similarly, GDB will silently ignore unrecognized stub feature responses, as long
    as each response uses one of the standard forms.

    Some features are flags. A stub which supports a flag feature should respond
    with a ‘`+`’ form response. Other features require values, and the stub should
    respond with an ‘`=`’ form response.

    Each feature has a default value, which GDB will use if ‘`qSupported`’ is not
    available or if the feature is not mentioned in the ‘`qSupported`’ response. The
    default values are fixed; a stub is free to omit any feature responses that
    match the defaults.

    Not all features can be probed, but for those which can, the probing mechanism
    is useful: in some cases, a stub’s internal architecture may not allow the
    protocol layer to know some information about the underlying target in advance.
    This is especially common in stubs which may be configured for multiple targets.

    These are the currently defined stub features and their properties:

    |  |  |  |  |
    | --- | --- | --- | --- |
    | Feature Name | Value Required | Default | Probe Allowed |
    | ‘`PacketSize`’ | Yes | ‘`-`’ | No |
    | ‘`qXfer:auxv:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:btrace:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:btrace-conf:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:exec-file:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:features:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:libraries:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:libraries-svr4:read`’ | No | ‘`-`’ | Yes |
    | ‘`augmented-libraries-svr4-read`’ | No | ‘`-`’ | No |
    | ‘`qXfer:memory-map:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:sdata:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:siginfo:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:siginfo:write`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:threads:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:traceframe-info:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:uib:read`’ | No | ‘`-`’ | Yes |
    | ‘`qXfer:fdpic:read`’ | No | ‘`-`’ | Yes |
    | ‘`Qbtrace:off`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace:bts`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace:pt`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace-conf:bts:size`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace-conf:pt:size`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace-conf:pt:ptwrite`’ | Yes | ‘`-`’ | Yes |
    | ‘`Qbtrace-conf:pt:event-tracing`’ | Yes | ‘`-`’ | Yes |
    | ‘`QNonStop`’ | No | ‘`-`’ | Yes |
    | ‘`QCatchSyscalls`’ | No | ‘`-`’ | Yes |
    | ‘`QPassSignals`’ | No | ‘`-`’ | Yes |
    | ‘`QStartNoAckMode`’ | No | ‘`-`’ | Yes |
    | ‘`multiprocess`’ | No | ‘`-`’ | No |
    | ‘`ConditionalBreakpoints`’ | No | ‘`-`’ | No |
    | ‘`ConditionalTracepoints`’ | No | ‘`-`’ | No |
    | ‘`ReverseContinue`’ | No | ‘`-`’ | No |
    | ‘`ReverseStep`’ | No | ‘`-`’ | No |
    | ‘`TracepointSource`’ | No | ‘`-`’ | No |
    | ‘`QAgent`’ | No | ‘`-`’ | No |
    | ‘`QAllow`’ | No | ‘`-`’ | No |
    | ‘`QDisableRandomization`’ | No | ‘`-`’ | No |
    | ‘`EnableDisableTracepoints`’ | No | ‘`-`’ | No |
    | ‘`QTBuffer:size`’ | No | ‘`-`’ | No |
    | ‘`tracenz`’ | No | ‘`-`’ | No |
    | ‘`BreakpointCommands`’ | No | ‘`-`’ | No |
    | ‘`swbreak`’ | No | ‘`-`’ | No |
    | ‘`hwbreak`’ | No | ‘`-`’ | No |
    | ‘`fork-events`’ | No | ‘`-`’ | No |
    | ‘`vfork-events`’ | No | ‘`-`’ | No |
    | ‘`exec-events`’ | No | ‘`-`’ | No |
    | ‘`QThreadEvents`’ | No | ‘`-`’ | No |
    | ‘`QThreadOptions`’ | Yes | ‘`-`’ | No |
    | ‘`no-resumed`’ | No | ‘`-`’ | No |
    | ‘`memory-tagging`’ | No | ‘`-`’ | No |
    | ‘`error-message`’ | No | ‘`+`’ | No |
    | ‘`binary-upload`’ | No | ‘`-`’ | No |
    | ‘`single-inf-arg`’ | No | ‘`-`’ | No |
    | ‘`multi-wp-addr`’ | No | ‘`+`’ | No |

    These are the currently defined stub features, in more detail:

    ‘`PacketSize=bytes`’
    :   The remote stub can accept packets up to at least bytes in length. GDB will send
        packets up to this size for bulk transfers, and will never send larger packets.
        This is a limit on the data characters in the packet, not including the frame
        and checksum. There is no trailing NUL byte in a remote protocol packet; if the
        stub stores packets in a NUL-terminated format, it should allow an extra byte in
        its buffer for the NUL. If this stub feature is not supported, GDB guesses based
        on the size of the ‘`g`’ packet response.

    ‘`qXfer:auxv:read`’
    :   The remote stub understands the ‘`qXfer:auxv:read`’ packet (see [qXfer auxiliary
        vector read](#qXfer-auxiliary-vector-read)).

    ‘`qXfer:btrace:read`’
    :   The remote stub understands the ‘`qXfer:btrace:read`’ packet (see [qXfer btrace
        read](#qXfer-btrace-read)).

    ‘`qXfer:btrace-conf:read`’
    :   The remote stub understands the ‘`qXfer:btrace-conf:read`’ packet (see [qXfer
        btrace-conf read](#qXfer-btrace_002dconf-read)).

    ‘`qXfer:exec-file:read`’
    :   The remote stub understands the ‘`qXfer:exec-file:read`’ packet (see [qXfer
        executable filename read](#qXfer-executable-filename-read)).

    ‘`qXfer:features:read`’
    :   The remote stub understands the ‘`qXfer:features:read`’ packet (see [qXfer
        target description read](#qXfer-target-description-read)).

    ‘`qXfer:libraries:read`’
    :   The remote stub understands the ‘`qXfer:libraries:read`’ packet (see [qXfer
        library list read](#qXfer-library-list-read)).

    ‘`qXfer:libraries-svr4:read`’
    :   The remote stub understands the ‘`qXfer:libraries-svr4:read`’ packet (see [qXfer
        svr4 library list read](#qXfer-svr4-library-list-read)).

    ‘`augmented-libraries-svr4-read`’
    :   The remote stub understands the augmented form of the
        ‘`qXfer:libraries-svr4:read`’ packet (see [qXfer svr4 library list
        read](#qXfer-svr4-library-list-read)).

    ‘`qXfer:memory-map:read`’
    :   The remote stub understands the ‘`qXfer:memory-map:read`’ packet (see [qXfer
        memory map read](#qXfer-memory-map-read)).

    ‘`qXfer:sdata:read`’
    :   The remote stub understands the ‘`qXfer:sdata:read`’ packet (see [qXfer sdata
        read](#qXfer-sdata-read)).

    ‘`qXfer:siginfo:read`’
    :   The remote stub understands the ‘`qXfer:siginfo:read`’ packet (see [qXfer
        siginfo read](#qXfer-siginfo-read)).

    ‘`qXfer:siginfo:write`’
    :   The remote stub understands the ‘`qXfer:siginfo:write`’ packet (see [qXfer
        siginfo write](#qXfer-siginfo-write)).

    ‘`qXfer:threads:read`’
    :   The remote stub understands the ‘`qXfer:threads:read`’ packet (see [qXfer
        threads read](#qXfer-threads-read)).

    ‘`qXfer:traceframe-info:read`’
    :   The remote stub understands the ‘`qXfer:traceframe-info:read`’ packet (see
        [qXfer traceframe info read](#qXfer-traceframe-info-read)).

    ‘`qXfer:uib:read`’
    :   The remote stub understands the ‘`qXfer:uib:read`’ packet (see [qXfer unwind
        info block](#qXfer-unwind-info-block)).

    ‘`qXfer:fdpic:read`’
    :   The remote stub understands the ‘`qXfer:fdpic:read`’ packet (see [qXfer fdpic
        loadmap read](#qXfer-fdpic-loadmap-read)).

    ‘`QNonStop`’
    :   The remote stub understands the ‘`QNonStop`’ packet (see [QNonStop](#QNonStop)).

    ‘`QCatchSyscalls`’
    :   The remote stub understands the ‘`QCatchSyscalls`’ packet (see
        [QCatchSyscalls](#QCatchSyscalls)).

    ‘`QPassSignals`’
    :   The remote stub understands the ‘`QPassSignals`’ packet (see
        [QPassSignals](#QPassSignals)).

    ‘`QStartNoAckMode`’
    :   The remote stub understands the ‘`QStartNoAckMode`’ packet and prefers to
        operate in no-acknowledgment mode. See [Packet
        Acknowledgment](about:blank/Packet-Acknowledgment.html#Packet-Acknowledgment).

    ‘`multiprocess`’
    :   The remote stub understands the multiprocess extensions to the remote protocol
        syntax. The multiprocess extensions affect the syntax of thread IDs in both
        packets and replies (see [thread-id
        syntax](about:blank/Packets.html#thread_002did-syntax)), and add process IDs to
        the ‘`D`’ packet and ‘`W`’ and ‘`X`’ replies. Note that reporting this feature
        indicates support for the syntactic extensions only, not that the stub
        necessarily supports debugging of more than one process at a time. The stub must
        not use multiprocess extensions in packet replies unless GDB has also indicated
        it supports them in its ‘`qSupported`’ request.

    ‘`qXfer:osdata:read`’
    :   The remote stub understands the ‘`qXfer:osdata:read`’ packet ((see [qXfer osdata
        read](#qXfer-osdata-read)).

    ‘`ConditionalBreakpoints`’
    :   The target accepts and implements evaluation of conditional expressions defined
        for breakpoints. The target will only report breakpoint triggers when such
        conditions are true (see [Break
        Conditions](about:blank/Conditions.html#Conditions)).

    ‘`ConditionalTracepoints`’
    :   The remote stub accepts and implements conditional expressions defined for
        tracepoints (see [Tracepoint
        Conditions](about:blank/Tracepoint-Conditions.html#Tracepoint-Conditions)).

    ‘`ReverseContinue`’
    :   The remote stub accepts and implements the reverse continue packet (see
        [bc](about:blank/Packets.html#bc)).

    ‘`ReverseStep`’
    :   The remote stub accepts and implements the reverse step packet (see
        [bs](about:blank/Packets.html#bs)).

    ‘`TracepointSource`’
    :   The remote stub understands the ‘`QTDPsrc`’ packet that supplies the source form
        of tracepoint definitions.

    ‘`QAgent`’
    :   The remote stub understands the ‘`QAgent`’ packet.

    ‘`QAllow`’
    :   The remote stub understands the ‘`QAllow`’ packet.

    ‘`QDisableRandomization`’
    :   The remote stub understands the ‘`QDisableRandomization`’ packet.

    ‘`StaticTracepoint`’
    :   The remote stub supports static tracepoints.

    ‘`InstallInTrace`’
    :   The remote stub supports installing tracepoint in tracing.

    ‘`EnableDisableTracepoints`’
    :   The remote stub supports the ‘`QTEnable`’ (see
        [QTEnable](about:blank/Tracepoint-Packets.html#QTEnable)) and ‘`QTDisable`’ (see
        [QTDisable](about:blank/Tracepoint-Packets.html#QTDisable)) packets that allow
        tracepoints to be enabled and disabled while a trace experiment is running.

    ‘`QTBuffer:size`’
    :   The remote stub supports the ‘`QTBuffer:size`’ (see
        [QTBuffer-size](about:blank/Tracepoint-Packets.html#QTBuffer_002dsize)) packet
        that allows to change the size of the trace buffer.

    ‘`tracenz`’
    :   The remote stub supports the ‘`tracenz`’ bytecode for collecting strings. See
        [Bytecode
        Descriptions](about:blank/Bytecode-Descriptions.html#Bytecode-Descriptions) for
        details about the bytecode.

    ‘`BreakpointCommands`’
    :   The remote stub supports running a breakpoint’s command list itself, rather than
        reporting the hit to GDB.

    ‘`Qbtrace:off`’
    :   The remote stub understands the ‘`Qbtrace:off`’ packet.

    ‘`Qbtrace:bts`’
    :   The remote stub understands the ‘`Qbtrace:bts`’ packet.

    ‘`Qbtrace:pt`’
    :   The remote stub understands the ‘`Qbtrace:pt`’ packet.

    ‘`Qbtrace-conf:bts:size`’
    :   The remote stub understands the ‘`Qbtrace-conf:bts:size`’ packet.

    ‘`Qbtrace-conf:pt:size`’
    :   The remote stub understands the ‘`Qbtrace-conf:pt:size`’ packet.

    ‘`Qbtrace-conf:pt:ptwrite`’
    :   The remote stub understands the ‘`Qbtrace-conf:pt:ptwrite`’ packet.

    ‘`Qbtrace-conf:pt:event-tracing`’
    :   The remote stub understands the ‘`Qbtrace-conf:pt:event-tracing`’ packet.

    ‘`swbreak`’
    :   The remote stub reports the ‘`swbreak`’ stop reason for memory breakpoints.

    ‘`hwbreak`’
    :   The remote stub reports the ‘`hwbreak`’ stop reason for hardware breakpoints.

    ‘`fork-events`’
    :   The remote stub reports the ‘`fork`’ stop reason for fork events.

    ‘`vfork-events`’
    :   The remote stub reports the ‘`vfork`’ stop reason for vfork events and vforkdone
        events.

    ‘`exec-events`’
    :   The remote stub reports the ‘`exec`’ stop reason for exec events.

    ‘`vContSupported`’
    :   The remote stub reports the supported actions in the reply to ‘`vCont?`’ packet.

    ‘`QThreadEvents`’
    :   The remote stub understands the ‘`QThreadEvents`’ packet.

    ‘`QThreadOptions=supported_options`’
    :   The remote stub understands the ‘`QThreadOptions`’ packet. supported_options
        indicates the set of thread options the remote stub supports. supported_options
        has the same format as the options parameter of the `QThreadOptions` packet,
        described at [QThreadOptions](#QThreadOptions).

    ‘`no-resumed`’
    :   The remote stub reports the ‘`N`’ stop reply.

    ‘`memory-tagging`’
    :   The remote stub supports and implements the required memory tagging
        functionality and understands the ‘`qMemTags`’ (see [qMemTags](#qMemTags)) and
        ‘`QMemTags`’ (see [QMemTags](#QMemTags)) packets.

        For AArch64 GNU/Linux systems, this feature can require access to the
        `/proc/pid/smaps` file so memory mapping page flags can be inspected, if
        ‘`qIsAddressTagged`’ (see [qIsAddressTagged](#qIsAddressTagged)) packet is not
        supported by the stub. Access to the `/proc/pid/smaps` file is done via
        ‘`vFile`’ requests.

    ‘`error-message`’
    :   The remote stub supports replying with an error in a ‘`E.errtext`’ (See [textual
        error reply](about:blank/Standard-Replies.html#textual-error-reply)) format from
        the ‘`m`’ and ‘`qRcmd`’ packets. It is not usually necessary to send this
        feature back to GDB in the ‘`qSupported`’ reply, GDB will always support
        ‘`E.errtext`’ format replies if it sent the ‘`error-message`’ feature.

    ‘`binary-upload`’
    :   The remote stub supports the ‘`x`’ packet (see [x
        packet](about:blank/Packets.html#x-packet)).

    ‘`single-inf-arg`’
    :   The remote stub would like to receive the inferior arguments as a single string
        within the ‘`vRun`’ packet. The stub should only send this feature if GDB sent
        ‘`single-inf-arg+`’ in the ‘`qSupported`’ packet.

    ‘`multi-wp-addr`’
    :   The remote stub supports sending multiple watchpoint addresses within ‘`T`’ stop
        reply packet. Stubs that don’t support this feature don’t need to tell GDB. Not
        supporting this feature just means sending back one watchpoint address instead
        of multiple, and GDB has always supported receiving a single watchpoint address.

‘`qSymbol::`’
:   Notify the target that GDB is prepared to serve symbol lookup requests. Accept
    requests from the target for the values of symbols.

    Reply:

    ‘`OK`’
    :   The target does not need to look up any (more) symbols.

    ‘`qSymbol:sym_name`’
    :   The target requests the value of symbol sym_name (hex encoded). GDB may provide
        the value by using the ‘`qSymbol:sym_value:sym_name`’ message, described below.

‘`qSymbol:sym_value:sym_name`’
:   Set the value of sym_name to sym_value.

    sym_name (hex encoded) is the name of a symbol whose value the target has
    previously requested.

    sym_value (hex) is the value for symbol sym_name. If GDB cannot supply a value
    for sym_name, then this field will be empty.

    Reply:

    ‘`OK`’
    :   The target does not need to look up any (more) symbols.

    ‘`qSymbol:sym_name`’
    :   The target requests the value of a new symbol sym_name (hex encoded). GDB will
        continue to supply the values of symbols (if available), until the target ceases
        to request them.

‘`qTBuffer`’

‘`QTBuffer`’

‘`QTDisconnected`’

‘`QTDP`’

‘`QTDPsrc`’

‘`QTDV`’

‘`qTfP`’

‘`qTfV`’

‘`QTFrame`’

‘`qTMinFTPILen`’
:   See [Tracepoint
    Packets](about:blank/Tracepoint-Packets.html#Tracepoint-Packets).

‘`qThreadExtraInfo,thread-id`’
:   Obtain from the target OS a printable string description of thread attributes
    for the thread thread-id; see [thread-id
    syntax](about:blank/Packets.html#thread_002did-syntax), for the forms of
    thread-id. This string may contain anything that the target OS thinks is
    interesting for GDB to tell the user about the thread. The string is displayed
    in GDB’s `info threads` display. Some examples of possible thread extra info
    strings are ‘`Runnable`’, or ‘`Blocked on Mutex`’.

    Reply:

    ‘`XX...`’
    :   Where ‘`XX...`’ is a hex encoding of ASCII data, comprising the printable string
        containing the extra information about the thread’s attributes.

    (Note that the `qThreadExtraInfo` packet’s name is separated from the command by
    a ‘`,`’, not a ‘`:`’, contrary to the naming conventions above. Please don’t use
    this packet as a model for new packets.)

‘`QTNotes`’

‘`qTP`’

‘`QTSave`’

‘`qTsP`’

‘`qTsV`’

‘`QTStart`’

‘`QTStop`’

‘`QTEnable`’

‘`QTDisable`’

‘`QTinit`’

‘`QTro`’

‘`qTStatus`’

‘`qTV`’

‘`qTfSTM`’

‘`qTsSTM`’

‘`qTSTMat`’
:   See [Tracepoint
    Packets](about:blank/Tracepoint-Packets.html#Tracepoint-Packets).

‘`qXfer:object:read:annex:offset,length`’
:   Read uninterpreted bytes from the target’s special data area identified by the
    keyword object. Request length bytes starting at offset bytes into the data. The
    content and encoding of annex is specific to object; it can supply additional
    details about what data to access.

    Reply:

    ‘`m data`’
    :   Data data (see [Binary Data](about:blank/Overview.html#Binary-Data)) has been
        read from the target. There may be more data at a higher address (although it is
        permitted to return ‘`m`’ even for the last valid block of data, as long as at
        least one byte of data was read). It is possible for data to have fewer bytes
        than the length in the request.

    ‘`l data`’
    :   Data data (see [Binary Data](about:blank/Overview.html#Binary-Data)) has been
        read from the target. There is no more data to be read. It is possible for data
        to have fewer bytes than the length in the request.

    ‘`l`’
    :   The offset in the request is at the end of the data. There is no more data to be
        read.

    Here are the specific requests of this form defined so far. All the
    ‘`qXfer:object:read:...`’ requests use the same reply formats, listed above.

    ‘`qXfer:auxv:read::offset,length`’
    :   Access the target’s *auxiliary vector*. See [auxiliary
        vector](about:blank/OS-Information.html#OS-Information). Note annex must be
        empty.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:btrace:read:annex:offset,length`’
    :   Return a description of the current branch trace. See [Branch Trace
        Format](about:blank/Branch-Trace-Format.html#Branch-Trace-Format). The annex
        part of the generic ‘`qXfer`’ packet may have one of the following values:

        `all`
        :   Returns all available branch trace.

        `new`
        :   Returns all available branch trace if the branch trace changed since the last
            read request.

        `delta`
        :   Returns the new branch trace since the last read request. Adds a new block to
            the end of the trace that begins at zero and ends at the source location of the
            first branch in the trace buffer. This extra block is used to stitch traces
            together.

            If the trace buffer overflowed, returns an error indicating the overflow.

        This packet is not probed by default; the remote stub must request it by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:btrace-conf:read::offset,length`’
    :   Return a description of the current branch trace configuration. See [Branch
        Trace Configuration
        Format](about:blank/Branch-Trace-Configuration-Format.html#Branch-Trace-Configuration-Format).

        This packet is not probed by default; the remote stub must request it by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:exec-file:read:annex:offset,length`’
    :   Return the full absolute name of the file that was executed to create a process
        running on the remote system. The annex specifies the numeric process ID of the
        process to query, encoded as a hexadecimal number. If the annex part is empty
        the remote stub should return the filename corresponding to the currently
        executing process.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:features:read:annex:offset,length`’
    :   Access the *target description*. See [Target
        Descriptions](about:blank/Target-Descriptions.html#Target-Descriptions). The
        annex specifies which XML document to access. The main description is always
        loaded from the ‘`target.xml`’ annex.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:libraries:read:annex:offset,length`’
    :   Access the target’s list of loaded libraries. See [Library List
        Format](about:blank/Library-List-Format.html#Library-List-Format). The annex
        part of the generic ‘`qXfer`’ packet must be empty (see [qXfer
        read](#qXfer-read)).

        Targets which maintain a list of libraries in the program’s memory do not need
        to implement this packet; it is designed for platforms where the operating
        system manages the list of loaded libraries.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:libraries-svr4:read:annex:offset,length`’
    :   Access the target’s list of loaded libraries when the target is an SVR4
        platform. See [Library List Format for SVR4
        Targets](about:blank/Library-List-Format-for-SVR4-Targets.html#Library-List-Format-for-SVR4-Targets).
        The annex part of the generic ‘`qXfer`’ packet must be empty unless the remote
        stub indicated it supports the augmented form of this packet by supplying an
        appropriate ‘`qSupported`’ response (see [qXfer read](#qXfer-read),
        [qSupported](#qSupported)).

        This packet is optional for better performance on SVR4 targets. GDB uses memory
        read packets to read the SVR4 library list otherwise.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

        If the remote stub indicates it supports the augmented form of this packet then
        the annex part of the generic ‘`qXfer`’ packet may contain a semicolon-separated
        list of ‘`name=value`’ arguments. The currently supported arguments are:

        `start=address`
        :   A hexadecimal number specifying the address of the ‘`struct link_map`’ to start
            reading the library list from. If unset or zero then the first ‘`struct
            link_map`’ in the library list will be chosen as the starting point.

        `prev=address`
        :   A hexadecimal number specifying the address of the ‘`struct link_map`’
            immediately preceding the ‘`struct link_map`’ specified by the ‘`start`’
            argument. If unset or zero then the remote stub will expect that no ‘`struct
            link_map`’ exists prior to the starting point.

        `lmid=lmid`
        :   A hexadecimal number specifying a namespace identifier. This is currently only
            used together with ‘`start`’ to provide the namespace identifier back to GDB in
            the response. GDB will only provide values that were previously reported to it.
            If unset, the response will include ‘`lmid="0x0"`’.

        Arguments that are not understood by the remote stub will be silently ignored.

    ‘`qXfer:memory-map:read::offset,length`’
    :   Access the target’s *memory-map*. See [Memory Map
        Format](about:blank/Memory-Map-Format.html#Memory-Map-Format). The annex part of
        the generic ‘`qXfer`’ packet must be empty (see [qXfer read](#qXfer-read)).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:sdata:read::offset,length`’
    :   Read contents of the extra collected static tracepoint marker information. The
        annex part of the generic ‘`qXfer`’ packet must be empty (see [qXfer
        read](#qXfer-read)). See [Tracepoint Action
        Lists](about:blank/Tracepoint-Actions.html#Tracepoint-Actions).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:siginfo:read::offset,length`’
    :   Read contents of the extra signal information on the target system. The annex
        part of the generic ‘`qXfer`’ packet must be empty (see [qXfer
        read](#qXfer-read)).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:threads:read::offset,length`’
    :   Access the list of threads on target. See [Thread List
        Format](about:blank/Thread-List-Format.html#Thread-List-Format). The annex part
        of the generic ‘`qXfer`’ packet must be empty (see [qXfer read](#qXfer-read)).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:traceframe-info:read::offset,length`’
    :   Return a description of the current traceframe’s contents. See [Traceframe Info
        Format](about:blank/Traceframe-Info-Format.html#Traceframe-Info-Format). The
        annex part of the generic ‘`qXfer`’ packet must be empty (see [qXfer
        read](#qXfer-read)).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:uib:read:pc:offset,length`’
    :   Return the unwind information block for pc. This packet is used on OpenVMS/ia64
        to ask the kernel unwind information.

        This packet is not probed by default.

    ‘`qXfer:fdpic:read:annex:offset,length`’
    :   Read contents of `loadmap`s on the target system. The annex, either ‘`exec`’ or
        ‘`interp`’, specifies which `loadmap`, executable `loadmap` or interpreter
        `loadmap` to read.

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

    ‘`qXfer:osdata:read::offset,length`’
    :   Access the target’s *operating system information*. See [Operating System
        Information](about:blank/Operating-System-Information.html#Operating-System-Information).

‘`qXfer:object:write:annex:offset:data...`’
:   Write uninterpreted bytes into the target’s special data area identified by the
    keyword object, starting at offset bytes into the data. The binary-encoded data
    (see [Binary Data](about:blank/Overview.html#Binary-Data)) to be written is
    given by data.... The content and encoding of annex is specific to object; it can
    supply additional details about what data to access.

    Reply:

    ‘`nn`’
    :   nn (hex encoded) is the number of bytes written. This may be fewer bytes than
        supplied in the request.

    Here are the specific requests of this form defined so far. All the
    ‘`qXfer:object:write:...`’ requests use the same reply formats, listed above.

    ‘`qXfer:siginfo:write::offset:data...`’
    :   Write data to the extra signal information on the target system. The annex part
        of the generic ‘`qXfer`’ packet must be empty (see [qXfer write](#qXfer-write)).

        This packet is not probed by default; the remote stub must request it, by
        supplying an appropriate ‘`qSupported`’ response (see
        [qSupported](#qSupported)).

‘`qXfer:object:operation:...`’
:   Requests of this form may be added in the future. When a stub does not recognize
    the object keyword, or its support for object does not recognize the operation
    keyword, the stub must respond with an empty packet.

‘`qAttached:pid`’
:   Return an indication of whether the remote server attached to an existing
    process or created a new process. When the multiprocess protocol extensions are
    supported (see [multiprocess extensions](#multiprocess-extensions)), pid is an
    integer in hexadecimal format identifying the target process. Otherwise, GDB
    will omit the pid field and the query packet will be simplified as
    ‘`qAttached`’.

    This query is used, for example, to know whether the remote process should be
    detached or killed when a GDB session is ended with the `quit` command.

    Reply:

    ‘`1`’
    :   The remote server attached to an existing process.

    ‘`0`’
    :   The remote server created a new process.

‘`qExecAndArgs`’
:   Return the program filename and arguments string with which the remote server
    was started, if the remote server was started with such things. If the remote
    server was started without the filename of a program to execute, or without any
    arguments, then the reply indicates this.

    Reply:

    ‘`U`’
    :   The program filename and arguments are unset. If GDB wants to start a new
        inferior, for example with ‘`vRun`’, then it will need to provide the filename
        of a program to use.

    ‘`S;prog;args;`’

    ‘`S;;args;`’
    :   The program filename provided to the remote server when it started was prog,
        which is a hex encoded string. The complete argument string passed to the
        inferior when it started as args, this is also a hex encoded string.

        If no arguments were passed when the inferior started then args be an empty
        string.

        It is valid for prog to be the empty string, this indicates that the server has
        no program set, GDB will need to supply a program name in order to start a new
        inferior. It is valid to reply with an empty prog and non-empty args, GDB will
        set the inferior arguments, but the user will need to supply a remote exec-file
        before an inferior can be started.

        The argument string args is passed directly to GDB as if to the `set args`
        command. And escaping required should be present in args, no changes are made by
        GDB.

‘`Qbtrace:bts`’
:   Enable branch tracing for the current thread using Branch Trace Store.

    Reply:

    ‘`OK`’
    :   Branch tracing has been enabled.

‘`Qbtrace:pt`’
:   Enable branch tracing for the current thread using Intel Processor Trace.

    Reply:

    ‘`OK`’
    :   Branch tracing has been enabled.

‘`Qbtrace:off`’
:   Disable branch tracing for the current thread.

    Reply:

    ‘`OK`’
    :   Branch tracing has been disabled.

‘`Qbtrace-conf:bts:size=value`’
:   Set the requested ring buffer size for new threads that use the btrace recording
    method in bts format.

    Reply:

    ‘`OK`’
    :   The ring buffer size has been set.

‘`Qbtrace-conf:pt:size=value`’
:   Set the requested ring buffer size for new threads that use the btrace recording
    method in pt format.

    Reply:

    ‘`OK`’
    :   The ring buffer size has been set.

‘`Qbtrace-conf:pt:ptwrite=(yes|no)`’
:   Indicate support for `PTWRITE` packets. This allows for backwards compatibility.

    Reply:

    ‘`OK`’
    :   The ptwrite config parameter has been set.

    ‘`E.errtext`’
    :   A badly formed request or an error was encountered.

‘`Qbtrace-conf:pt:event-tracing=(yes|no)`’
:   Indicate support for event-tracing packets. This allows for backwards
    compatibility.

    Reply:

    ‘`OK`’
    :   The event-tracing config parameter has been set.

    ‘`E.errtext`’
    :   A badly formed request or an error was encountered.