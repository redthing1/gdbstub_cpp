# Stop Reply Packets (Debugging with GDB)

The ‘`C`’, ‘`c`’, ‘`S`’, ‘`s`’, ‘`vCont`’, ‘`vAttach`’, ‘`vRun`’, ‘`vStopped`’,
and ‘`?`’ packets can receive any of the below as a reply. Except for ‘`?`’ and
‘`vStopped`’, that reply is only returned when the target halts. In the below
the exact meaning of *signal number* is defined by the header
`include/gdb/signals.h` in the GDB source code.

In non-stop mode, the server will simply reply ‘`OK`’ to commands such as
‘`vCont`’; any stop will be the subject of a future notification. See [Remote
Non-Stop](about:blank/Remote-Non_002dStop.html#Remote-Non_002dStop).

As in the description of request packets, we include spaces in the reply
templates for clarity; these are not part of the reply packet’s syntax. No GDB
stop reply packet uses spaces to separate its components.

‘`S AA`’
:   The program received signal number AA (a two-digit hexadecimal number). This is
    equivalent to a ‘`T`’ response with no n:r pairs.

‘`T AA n1:r1;n2:r2;...`’
:   The program received signal number AA (a two-digit hexadecimal number). This is
    equivalent to an ‘`S`’ response, except that the ‘`n:r`’ pairs can carry values
    of important registers and other information directly in the stop reply packet,
    reducing round-trip latency. Single-step and breakpoint traps are reported this
    way. Each ‘`n:r`’ pair is interpreted as follows:

    - If n is a hexadecimal number, it is a register number, and the corresponding r gives that register’s value. The data r is a series of bytes in target byte order, with each byte given by a two-digit hex number.
    - If n is ‘`thread`’, then r is the thread ID of the stopped thread, as specified in [thread-id syntax](about:blank/Packets.html#thread_002did-syntax).
    - If n is ‘`core`’, then r is the hexadecimal number of the core on which the stop event was detected.
    - If n is a recognized *stop reason*, it describes a more specific event that stopped the target. The currently defined stop reasons are listed below. The aa should be ‘`05`’, the trap signal. At most one stop reason should be present.
    - Otherwise, GDB should ignore this ‘`n:r`’ pair and go on to the next; this allows us to extend the protocol in the future.

    The currently defined stop reasons are:

    ‘`watch`’

    ‘`rwatch`’

    ‘`awatch`’
    :   The packet indicates a watchpoint hit, and r is the data address, in hex.

        Some targets, for example AArch64, are unable to accurately report the address
        which triggered a watchpoint trap. As a consequence, multiple watched addresses
        could explain a single watchpoint trap.

        If GDB sent the ‘`multi-wp-addr`’ feature flag in its ‘`qSupported`’ packet (see
        [multi-wp-addr
        feature](about:blank/General-Query-Packets.html#multi_002dwp_002daddr-feature)),
        then multiple instances of these stop reasons can appear in a single ‘`T`’ stop
        reply packet. GDB will select between the multiple reported watchpoint addresses
        when displaying the stop to the user.

        If the ‘`multi-wp-addr`’ was not sent by GDB, then GDB only expects one
        watchpoint related stop address in a single ‘`T`’ packet. The server must select
        the most likely watchpoint address.

    ‘`syscall_entry`’

    ‘`syscall_return`’
    :   The packet indicates a syscall entry or return, and r is the syscall number, in
        hex.

    ‘`library`’
    :   The packet indicates that the loaded libraries have changed. GDB should use
        ‘`qXfer:libraries:read`’ to fetch a new list of loaded libraries. The r part is
        ignored.

    ‘`replaylog`’
    :   The packet indicates that the target cannot continue replaying logged execution
        events, because it has reached the end (or the beginning when executing
        backward) of the log. The value of r will be either ‘`begin`’ or ‘`end`’. See
        [Reverse Execution](about:blank/Reverse-Execution.html#Reverse-Execution), for
        more information.

    ‘`swbreak`’
    :   The packet indicates a software breakpoint instruction was executed,
        irrespective of whether it was GDB that planted the breakpoint or the breakpoint
        is hardcoded in the program. The r part must be left empty.

        On some architectures, such as x86, at the architecture level, when a breakpoint
        instruction executes the program counter points at the breakpoint address plus
        an offset. On such targets, the stub is responsible for adjusting the PC to
        point back at the breakpoint address.

        This packet should not be sent by default; older GDB versions did not support
        it. GDB requests it, by supplying an appropriate ‘`qSupported`’ feature (see
        [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
        stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

        This packet is required for correct non-stop mode operation.

    ‘`hwbreak`’
    :   The packet indicates the target stopped for a hardware breakpoint. The r part
        must be left empty.

        The same remarks about ‘`qSupported`’ and non-stop mode above apply.

    ‘`fork`’
    :   The packet indicates that `fork` was called, and r is the thread ID of the new
        child process, as specified in [thread-id
        syntax](about:blank/Packets.html#thread_002did-syntax). This packet is only
        applicable to targets that support fork events.

        This packet should not be sent by default; older GDB versions did not support
        it. GDB requests it, by supplying an appropriate ‘`qSupported`’ feature (see
        [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
        stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

    ‘`vfork`’
    :   The packet indicates that `vfork` was called, and r is the thread ID of the new
        child process, as specified in [thread-id
        syntax](about:blank/Packets.html#thread_002did-syntax). This packet is only
        applicable to targets that support vfork events.

        This packet should not be sent by default; older GDB versions did not support
        it. GDB requests it, by supplying an appropriate ‘`qSupported`’ feature (see
        [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
        stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

    ‘`vforkdone`’
    :   The packet indicates that a child process created by a vfork has either called
        `exec` or terminated, so that the address spaces of the parent and child process
        are no longer shared. The r part is ignored. This packet is only applicable to
        targets that support vforkdone events.

        This packet should not be sent by default; older GDB versions did not support
        it. GDB requests it, by supplying an appropriate ‘`qSupported`’ feature (see
        [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
        stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

    ‘`exec`’
    :   The packet indicates that `execve` was called, and r is the absolute pathname of
        the file that was executed, in hex. This packet is only applicable to targets
        that support exec events.

        This packet should not be sent by default; older GDB versions did not support
        it. GDB requests it, by supplying an appropriate ‘`qSupported`’ feature (see
        [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
        stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

    ‘`clone`’
    :   The packet indicates that `clone` was called, and r is the thread ID of the new
        child thread, as specified in [thread-id
        syntax](about:blank/Packets.html#thread_002did-syntax). This packet is only
        applicable to targets that support clone events.

        This packet should not be sent by default; GDB requests it with the
        [QThreadOptions](about:blank/General-Query-Packets.html#QThreadOptions) packet.

    ‘`create`’
    :   The packet indicates that the thread was just created. The new thread is stopped
        until GDB sets it running with a resumption packet (see [vCont
        packet](about:blank/Packets.html#vCont-packet)). This packet should not be sent
        by default; GDB requests it with the
        [QThreadEvents](about:blank/General-Query-Packets.html#QThreadEvents) packet.
        See also the ‘`w`’ (see [thread exit event](#thread-exit-event)) remote reply
        below. The r part is ignored.

‘`W AA`’

‘`W AA ; process:pid`’
:   The process exited, and AA is the exit status. This is only applicable to
    certain targets.

    The second form of the response, including the process ID of the exited process,
    can be used only when GDB has reported support for multiprocess protocol
    extensions; see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions).
    Both AA and pid are formatted as big-endian hex strings.

‘`X AA`’

‘`X AA ; process:pid`’
:   The process terminated with signal AA.

    The second form of the response, including the process ID of the terminated
    process, can be used only when GDB has reported support for multiprocess
    protocol extensions; see [multiprocess
    extensions](about:blank/General-Query-Packets.html#multiprocess-extensions).
    Both AA and pid are formatted as big-endian hex strings.

‘`w AA ; tid`’
:   The thread exited, and AA is the exit status. This response should not be sent
    by default; GDB requests it with either the
    [QThreadEvents](about:blank/General-Query-Packets.html#QThreadEvents) or
    [QThreadOptions](about:blank/General-Query-Packets.html#QThreadOptions) packets.
    See also [thread create event](#thread-create-event) above. AA is formatted as a
    big-endian hex string.

‘`N`’
:   There are no resumed threads left in the target. In other words, even though the
    process is alive, the last resumed thread has exited. For example, say the
    target process has two threads: thread 1 and thread 2. The client leaves thread
    1 stopped, and resumes thread 2, which subsequently exits. At this point, even
    though the process is still alive, and thus no ‘`W`’ stop reply is sent, no
    thread is actually executing either. The ‘`N`’ stop reply thus informs the
    client that it can stop waiting for stop replies. This packet should not be sent
    by default; older GDB versions did not support it. GDB requests it, by supplying
    an appropriate ‘`qSupported`’ feature (see
    [qSupported](about:blank/General-Query-Packets.html#qSupported)). The remote
    stub must also supply the appropriate ‘`qSupported`’ feature indicating support.

‘`O XX...`’
:   ‘`XX...`’ is hex encoding of ASCII data, to be written as the program’s console
    output. This can happen at any time while the program is running and the
    debugger should continue to wait for ‘`W`’, ‘`T`’, etc. This reply is not
    permitted in non-stop mode.

‘`F call-id,parameter...`’
:   call-id is the identifier which says which host system call should be called.
    This is just the name of the function. Translation into the correct system call
    is only applicable as it’s defined in GDB. See [File-I/O Remote Protocol
    Extension](about:blank/File_002dI_002fO-Remote-Protocol-Extension.html#File_002dI_002fO-Remote-Protocol-Extension),
    for a list of implemented system calls.

    ‘`parameter...`’ is a list of parameters as defined for this very system call.

    The target replies with this packet when it expects GDB to call a host system
    call on behalf of the target. GDB replies with an appropriate ‘`F`’ packet and
    keeps up waiting for the next reply packet from the target. The latest ‘`C`’,
    ‘`c`’, ‘`S`’ or ‘`s`’ action is expected to be continued. See [File-I/O Remote
    Protocol
    Extension](about:blank/File_002dI_002fO-Remote-Protocol-Extension.html#File_002dI_002fO-Remote-Protocol-Extension),
    for more details.