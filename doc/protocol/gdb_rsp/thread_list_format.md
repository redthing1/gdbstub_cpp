# Thread List Format (Debugging with GDB)

---

### E.18 Thread List Format

To efficiently update the list of threads and their attributes, GDB issues the
‘`qXfer:threads:read`’ packet (see [qXfer threads
read](about:blank/General-Query-Packets.html#qXfer-threads-read)) and obtains
the XML document with the following structure:

```
<?xml version="1.0"?>
<threads>
    <thread id="id" core="0" name="name" id_str="Thread 12.34" handle="1a2b3c">
    ... description ...
    </thread>
</threads>
```

Each ‘`thread`’ element must have the ‘`id`’ attribute that identifies the
thread (see [thread-id syntax](about:blank/Packets.html#thread_002did-syntax)).
The ‘`core`’ attribute, if present, specifies which processor core the thread
was last executing on. The ‘`name`’ attribute, if present, specifies the
human-readable name of the thread. The content of the of ‘`thread`’ element is
interpreted as human-readable auxiliary information. The ‘`id_str`’ attribute,
if present, specifies what GDB should print as the target ID of the thread (e.g.
in the ‘`info threads`’ command or when switching to the thread). The ‘`handle`’
attribute, if present, is a hex encoded representation of the thread handle.