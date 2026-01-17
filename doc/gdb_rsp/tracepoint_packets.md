# Tracepoint Packets (Debugging with GDB)

Here we describe the packets GDB uses to implement tracepoints (see
[Tracepoints](about:blank/Tracepoints.html#Tracepoints)).

‘`QTDP:n:addr:ena:step:pass[:Fflen][:S][:Xlen,bytes][-]`’
:   Create a new tracepoint, number n, at addr. If ena is ‘`E`’, then the tracepoint
    is enabled; if it is ‘`D`’, then the tracepoint is disabled. The step gives the
    tracepoint’s step count, and pass gives its pass count. If an ‘`F`’ is present,
    then the tracepoint is to be a fast tracepoint, and the flen is the number of
    bytes that the target should copy elsewhere to make room for the tracepoint. If
    an ‘`S`’ is present, the tracepoint is to be a static tracepoint. If an ‘`X`’ is
    present, it introduces a tracepoint condition, which consists of a hexadecimal
    length, followed by a comma and hex-encoded bytes, in a manner similar to action
    encodings as described below. If the trailing ‘`-`’ is present, further ‘`QTDP`’
    packets will follow to specify this tracepoint’s actions.

    Replies:

    ‘`OK`’
    :   The packet was understood and carried out.

    ‘`qRelocInsn`’
    :   See [Relocate instruction reply packet](#Tracepoint-Packets).

‘`QTDP:-n:addr:[S]action...[-]`’
:   Define actions to be taken when a tracepoint is hit. The n and addr must be the
    same as in the initial ‘`QTDP`’ packet for this tracepoint. This packet may only
    be sent immediately after another ‘`QTDP`’ packet that ended with a ‘`-`’. If
    the trailing ‘`-`’ is present, further ‘`QTDP`’ packets will follow, specifying
    more actions for this tracepoint.

    In the series of action packets for a given tracepoint, at most one can have an
    ‘`S`’ before its first action. If such a packet is sent, it and the following
    packets define “while-stepping” actions. Any prior packets define ordinary
    actions -- that is, those taken when the tracepoint is first hit. If no action
    packet has an ‘`S`’, then all the packets in the series specify ordinary
    tracepoint actions.

    The ‘`action...`’ portion of the packet is a series of actions, concatenated
    without separators. Each action has one of the following forms:

    ‘`R mask`’
    :   Collect the registers whose bits are set in mask, a hexadecimal number whose
        i’th bit is set if register number i should be collected. (The least significant
        bit is numbered zero.) Note that mask may be any number of digits long; it may
        not fit in a 32-bit word.

    ‘`M basereg,offset,len`’
    :   Collect len bytes of memory starting at the address in register number basereg,
        plus offset. If basereg is ‘`-1`’, then the range has a fixed address: offset is
        the address of the lowest byte to collect. The basereg, offset, and len
        parameters are all unsigned hexadecimal values (the ‘`-1`’ value for basereg is
        a special case).

    ‘`X len,expr`’
    :   Evaluate expr, whose length is len, and collect memory as it directs. The agent
        expression expr is as described in [Agent
        Expressions](about:blank/Agent-Expressions.html#Agent-Expressions). Each byte of
        the expression is encoded as a two-digit hex number in the packet; len is the
        number of bytes in the expression (and thus one-half the number of hex digits in
        the packet).

    ‘`L`’
    :   Collect static trace data.

    Any number of actions may be packed together in a single ‘`QTDP`’ packet, as
    long as the packet does not exceed the maximum packet length (400 bytes, for
    many stubs). There may be only one ‘`R`’ action per tracepoint, and it must
    precede any ‘`M`’ or ‘`X`’ actions. Any registers referred to by ‘`M`’ and ‘`X`’
    actions must be collected by a preceding ‘`R`’ action. (The “while-stepping”
    actions are treated as if they were attached to a separate tracepoint, as far as
    these restrictions are concerned.)

    Replies:

    ‘`OK`’
    :   The packet was understood and carried out.

    ‘`qRelocInsn`’
    :   See [Relocate instruction reply packet](#Tracepoint-Packets).

‘`QTDPsrc:n:addr:type:start:slen:bytes`’
:   Specify a source string of tracepoint n at address addr. This is useful to get
    accurate reproduction of the tracepoints originally downloaded at the beginning
    of the trace run. The type is the name of the tracepoint part, such as ‘`cond`’
    for the tracepoint’s conditional expression (see below for a list of types),
    while bytes is the string, encoded in hexadecimal.

    start is the offset of the bytes within the overall source string, while slen is
    the total length of the source string. This is intended for handling source
    strings that are longer than will fit in a single packet.

    The available string types are ‘`at`’ for the location, ‘`cond`’ for the
    conditional, and ‘`cmd`’ for an action command. GDB sends a separate packet for
    each command in the action list, in the same order in which the commands are
    stored in the list.

    The target does not need to do anything with source strings except report them
    back as part of the replies to the ‘`qTfP`’/‘`qTsP`’ query packets.

    Although this packet is optional, and GDB will only send it if the target
    replies with ‘`TracepointSource`’ See [General Query
    Packets](about:blank/General-Query-Packets.html#General-Query-Packets), it makes
    both disconnected tracing and trace files much easier to use. Otherwise the user
    must be careful that the tracepoints in effect while looking at trace frames are
    identical to the ones in effect during the trace run; even a small discrepancy
    could cause ‘`tdump`’ not to work, or a particular trace frame not be found.

‘`QTDV:n:value:builtin:name`’
:   Create a new trace state variable, number n, with an initial value of value,
    which is a 64-bit signed integer. Both n and value are encoded as hexadecimal
    values. GDB has the option of not using this packet for initial values of zero;
    the target should simply create the trace state variables as they are mentioned
    in expressions. The value builtin should be 1 (one) if the trace state variable
    is builtin and 0 (zero) if it is not builtin. GDB only sets builtin to 1 if a
    previous ‘`qTfV`’ or ‘`qTsV`’ packet had it set. The contents of name is the
    hex-encoded name (without the leading ‘`$`’) of the trace state variable.

‘`QTFrame:n`’
:   Select the n’th tracepoint frame from the buffer, and use the register and
    memory contents recorded there to answer subsequent request packets from GDB.

    A successful reply from the stub indicates that the stub has found the requested
    frame. The response is a series of parts, concatenated without separators,
    describing the frame we selected. Each part has one of the following forms:

    ‘`F f`’
    :   The selected frame is number n in the trace frame buffer; f is a hexadecimal
        number. If f is ‘`-1`’, then there was no frame matching the criteria in the
        request packet.

    ‘`T t`’
    :   The selected trace frame records a hit of tracepoint number t; t is a
        hexadecimal number.

‘`QTFrame:pc:addr`’
:   Like ‘`QTFrame:n`’, but select the first tracepoint frame after the currently
    selected frame whose PC is addr; addr is a hexadecimal number.

‘`QTFrame:tdp:t`’
:   Like ‘`QTFrame:n`’, but select the first tracepoint frame after the currently
    selected frame that is a hit of tracepoint t; t is a hexadecimal number.

‘`QTFrame:range:start:end`’
:   Like ‘`QTFrame:n`’, but select the first tracepoint frame after the currently
    selected frame whose PC is between start (inclusive) and end (inclusive); start
    and end are hexadecimal numbers.

‘`QTFrame:outside:start:end`’
:   Like ‘`QTFrame:range:start:end`’, but select the first frame *outside* the given
    range of addresses (exclusive).

‘`qTMinFTPILen`’
:   This packet requests the minimum length of instruction at which a fast
    tracepoint (see [Set
    Tracepoints](about:blank/Set-Tracepoints.html#Set-Tracepoints)) may be placed.
    For instance, on the 32-bit x86 architecture, it is possible to use a 4-byte
    jump, but it depends on the target system being able to create trampolines in
    the first 64K of memory, which might or might not be possible for that system.
    So the reply to this packet will be 4 if it is able to arrange for that.

    Replies:

    ‘`0`’
    :   The minimum instruction length is currently unknown.

    ‘`length`’
    :   The minimum instruction length is length, where length is a hexadecimal number
        greater or equal to 1. A reply of 1 means that a fast tracepoint may be placed
        on any instruction regardless of size.

    ‘`E`’
    :   An error has occurred.

‘`QTStart`’
:   Begin the tracepoint experiment. Begin collecting data from tracepoint hits in
    the trace frame buffer. This packet supports the ‘`qRelocInsn`’ reply (see
    [Relocate instruction reply packet](#Tracepoint-Packets)).

‘`QTStop`’
:   End the tracepoint experiment. Stop collecting trace frames.

‘`QTEnable:n:addr`’
:   Enable tracepoint n at address addr in a started tracepoint experiment. If the
    tracepoint was previously disabled, then collection of data from it will resume.

‘`QTDisable:n:addr`’
:   Disable tracepoint n at address addr in a started tracepoint experiment. No more
    data will be collected from the tracepoint unless ‘`QTEnable:n:addr`’ is
    subsequently issued.

‘`QTinit`’
:   Clear the table of tracepoints, and empty the trace frame buffer.

‘`QTro:start1,end1:start2,end2:...`’
:   Establish the given ranges of memory as “transparent”. The stub will answer
    requests for these ranges from memory’s current contents, if they were not
    collected as part of the tracepoint hit.

    GDB uses this to mark read-only regions of memory, like those containing program
    code. Since these areas never change, they should still have the same contents
    they did when the tracepoint was hit, so there’s no reason for the stub to
    refuse to provide their contents.

‘`QTDisconnected:value`’
:   Set the choice to what to do with the tracing run when GDB disconnects from the
    target. A value of 1 directs the target to continue the tracing run, while 0
    tells the target to stop tracing if GDB is no longer in the picture.

‘`qTStatus`’
:   Ask the stub if there is a trace experiment running right now.

    The reply has the form:

    ‘`Trunning[;field]...`’
    :   running is a single digit `1` if the trace is presently running, or `0` if not.
        It is followed by semicolon-separated optional fields that an agent may use to
        report additional status.

    If the trace is not running, the agent may report any of several explanations as
    one of the optional fields:

    ‘`tnotrun:0`’
    :   No trace has been run yet.

    ‘`tstop[:text]:0`’
    :   The trace was stopped by a user-originated stop command. The optional text field
        is a user-supplied string supplied as part of the stop command (for instance, an
        explanation of why the trace was stopped manually). It is hex-encoded.

    ‘`tfull:0`’
    :   The trace stopped because the trace buffer filled up.

    ‘`tdisconnected:0`’
    :   The trace stopped because GDB disconnected from the target.

    ‘`tpasscount:tpnum`’
    :   The trace stopped because tracepoint tpnum exceeded its pass count.

    ‘`terror:text:tpnum`’
    :   The trace stopped because tracepoint tpnum had an error. The string text is
        available to describe the nature of the error (for instance, a divide by zero in
        the condition expression); it is hex encoded.

    ‘`tunknown:0`’
    :   The trace stopped for some other reason.

    Additional optional fields supply statistical and other information. Although
    not required, they are extremely useful for users monitoring the progress of a
    trace run. If a trace has stopped, and these numbers are reported, they must
    reflect the state of the just-stopped trace.

    ‘`tframes:n`’
    :   The number of trace frames in the buffer.

    ‘`tcreated:n`’
    :   The total number of trace frames created during the run. This may be larger than
        the trace frame count, if the buffer is circular.

    ‘`tsize:n`’
    :   The total size of the trace buffer, in bytes.

    ‘`tfree:n`’
    :   The number of bytes still unused in the buffer.

    ‘`circular:n`’
    :   The value of the circular trace buffer flag. `1` means that the trace buffer is
        circular and old trace frames will be discarded if necessary to make room, `0`
        means that the trace buffer is linear and may fill up.

    ‘`disconn:n`’
    :   The value of the disconnected tracing flag. `1` means that tracing will continue
        after GDB disconnects, `0` means that the trace run will stop.

‘`qTP:tp:addr`’
:   Ask the stub for the current state of tracepoint number tp at address addr.

    Replies:

    ‘`Vhits:usage`’
    :   The tracepoint has been hit hits times so far during the trace run, and accounts
        for usage in the trace buffer. Note that `while-stepping` steps are not counted
        as separate hits, but the steps’ space consumption is added into the usage
        number.

‘`qTV:var`’
:   Ask the stub for the value of the trace state variable number var.

    Replies:

    ‘`Vvalue`’
    :   The value of the variable is value. This will be the current value of the
        variable if the user is examining a running target, or a saved value if the
        variable was collected in the trace frame that the user is looking at. Note that
        multiple requests may result in different reply values, such as when requesting
        values while the program is running.

    ‘`U`’
    :   The value of the variable is unknown. This would occur, for example, if the user
        is examining a trace frame in which the requested variable was not collected.

‘`qTfP`’

‘`qTsP`’
:   These packets request data about tracepoints that are being used by the target.
    GDB sends `qTfP` to get the first piece of data, and multiple `qTsP` to get
    additional pieces. Replies to these packets generally take the form of the
    `QTDP` packets that define tracepoints. (FIXME add detailed syntax)

‘`qTfV`’

‘`qTsV`’
:   These packets request data about trace state variables that are on the target.
    GDB sends `qTfV` to get the first vari of data, and multiple `qTsV` to get
    additional variables. Replies to these packets follow the syntax of the `QTDV`
    packets that define trace state variables.

‘`qTfSTM`’

‘`qTsSTM`’
:   These packets request data about static tracepoint markers that exist in the
    target program. GDB sends `qTfSTM` to get the first piece of data, and multiple
    `qTsSTM` to get additional pieces. Replies to these packets take the following
    form:

    Reply:

    ‘`m address:id:extra`’
    :   A single marker

    ‘`m address:id:extra,address:id:extra...`’
    :   a comma-separated list of markers

    ‘`l`’
    :   (lower case letter ‘`L`’) denotes end of list.

    The address is encoded in hex; id and extra are strings encoded in hex.

    In response to each query, the target will reply with a list of one or more
    markers, separated by commas. GDB will respond to each reply with a request for
    more markers (using the ‘`qs`’ form of the query), until the target responds
    with ‘`l`’ (lower-case ell, for *last*).

‘`qTSTMat:address`’
:   This packet requests data about static tracepoint markers in the target program
    at address. Replies to this packet follow the syntax of the `qTfSTM` and
    `qTsSTM` packets that list static tracepoint markers.

‘`QTSave:filename`’
:   This packet directs the target to save trace data to the file name filename in
    the target’s filesystem. The filename is encoded as a hex string; the
    interpretation of the file name (relative vs absolute, wild cards, etc) is up to
    the target.

‘`qTBuffer:offset,len`’
:   Return up to len bytes of the current contents of trace buffer, starting at
    offset. The trace buffer is treated as if it were a contiguous collection of
    traceframes, as per the trace file format. The reply consists as many
    hex-encoded bytes as the target can deliver in a packet; it is not an error to
    return fewer than were asked for. A reply consisting of just `l` indicates that
    no bytes are available.

‘`QTBuffer:circular:value`’
:   This packet directs the target to use a circular trace buffer if value is 1, or
    a linear buffer if the value is 0.

‘`QTBuffer:size:size`’
:   This packet directs the target to make the trace buffer be of size size if
    possible. A value of `-1` tells the target to use whatever size it prefers.

‘`QTNotes:[type:text][;type:text]...`’
:   This packet adds optional textual notes to the trace run. Allowable types
    include `user`, `notes`, and `tstop`, the text fields are arbitrary strings,
    hex-encoded.

When installing fast tracepoints in memory, the target may need to relocate the
instruction currently at the tracepoint address to a different address in
memory. For most instructions, a simple copy is enough, but, for example, call
instructions that implicitly push the return address on the stack, and relative
branches or other PC-relative instructions require offset adjustment, so that
the effect of executing the instruction at a different address is the same as if
it had executed in the original location.

In response to several of the tracepoint packets, the target may also respond
with a number of intermediate ‘`qRelocInsn`’ request packets before the final
result packet, to have GDB handle this relocation operation. If a packet
supports this mechanism, its documentation will explicitly say so. See for
example the above descriptions for the ‘`QTStart`’ and ‘`QTDP`’ packets. The
format of the request is: