# Host I/O Packets (Debugging with GDB)

The *Host I/O* packets allow GDB to perform I/O operations on the far side of a
remote link. For example, Host I/O is used to upload and download files to a
remote target with its own filesystem. Host I/O uses the same constant values
and data structure layout as the target-initiated File-I/O protocol. However,
the Host I/O packets are structured differently. The target-initiated protocol
relies on target memory to store parameters and buffers. Host I/O requests are
initiated by GDB, and the target’s memory is not involved. See [File-I/O Remote
Protocol
Extension](about:blank/File_002dI_002fO-Remote-Protocol-Extension.html#File_002dI_002fO-Remote-Protocol-Extension),
for more details on the target-initiated protocol.

The Host I/O request packets all encode a single operation along with its
arguments. They have this format:

‘`vFile:open: filename, flags, mode`’
:   Open a file at filename and return a file descriptor for it, or return -1 if an
    error occurs. The filename is a string, flags is an integer indicating a mask of
    open flags (see [Open Flags](about:blank/Open-Flags.html#Open-Flags)), and mode
    is an integer indicating a mask of mode bits to use if the file is created (see
    [mode_t Values](about:blank/mode_005ft-Values.html#mode_005ft-Values)). See
    [open](about:blank/open.html#open), for details of the open flags and mode
    values.

‘`vFile:close: fd`’
:   Close the open file corresponding to fd and return 0, or -1 if an error occurs.

‘`vFile:pread: fd, count, offset`’
:   Read data from the open file corresponding to fd. Up to count bytes will be read
    from the file, starting at offset relative to the start of the file. The target
    may read fewer bytes; common reasons include packet size limits and an
    end-of-file condition. The number of bytes read is returned. Zero should only be
    returned for a successful read at the end of the file, or if count was zero.

    The data read should be returned as a binary attachment on success. If zero
    bytes were read, the response should include an empty binary attachment (i.e. a
    trailing semicolon). The return value is the number of target bytes read; the
    binary attachment may be longer if some characters were escaped.

‘`vFile:pwrite: fd, offset, data`’
:   Write data (a binary buffer) to the open file corresponding to fd. Start the
    write at offset from the start of the file. Unlike many `write` system calls,
    there is no separate count argument; the length of data in the packet is used.
    ‘`vFile:pwrite`’ returns the number of bytes written, which may be shorter than
    the length of data, or -1 if an error occurred.

‘`vFile:fstat: fd`’
:   Get information about the open file corresponding to fd. On success the
    information is returned as a binary attachment and the return value is the size
    of this attachment in bytes. If an error occurs the return value is -1. The
    format of the returned binary attachment is as described in [struct
    stat](about:blank/struct-stat.html#struct-stat).

‘`vFile:stat: filename`’
:   Get information about the file filename on the target as if from a ‘`stat`’
    call. On success the information is returned as a binary attachment and the
    return value is the size of this attachment in bytes. If an error occurs the
    return value is -1. The format of the returned binary attachment is as described
    in [struct stat](about:blank/struct-stat.html#struct-stat).

    If filename is a symbolic link, then the information returned is about the file
    the link refers to, this is inline with the ‘`stat`’ library call.

‘`vFile:lstat: filename`’
:   Get information about the file filename on the target as if from an ‘`lstat`’
    call. On success the information is returned as a binary attachment and the
    return value is the size of this attachment in bytes. If an error occurs the
    return value is -1. The format of the returned binary attachment is as described
    in [struct stat](about:blank/struct-stat.html#struct-stat).

    This packet is identical to ‘`vFile:stat`’, except if filename is a symbolic
    link, then this packet returns information about the link itself, not the file
    that the link refers to, this is inline with the ‘`lstat`’ library call.

‘`vFile:unlink: filename`’
:   Delete the file at filename on the target. Return 0, or -1 if an error occurs.
    The filename is a string.

‘`vFile:readlink: filename`’
:   Read value of symbolic link filename on the target. Return the number of bytes
    read, or -1 if an error occurs.

    The data read should be returned as a binary attachment on success. If zero
    bytes were read, the response should include an empty binary attachment (i.e. a
    trailing semicolon). The return value is the number of target bytes read; the
    binary attachment may be longer if some characters were escaped.

‘`vFile:setfs: pid`’
:   Select the filesystem on which `vFile` operations with filename arguments will
    operate. This is required for GDB to be able to access files on remote targets
    where the remote stub does not share a common filesystem with the inferior(s).

    If pid is nonzero, select the filesystem as seen by process pid. If pid is zero,
    select the filesystem as seen by the remote stub. Return 0 on success, or -1 if
    an error occurs. If `vFile:setfs:` indicates success, the selected filesystem
    remains selected until the next successful `vFile:setfs:` operation.