# Library List Format for SVR4 Targets (Debugging with GDB)

---

### E.16 Library List Format for SVR4 Targets

On SVR4 platforms GDB can use the symbol table of a dynamic loader (e.g.
`ld.so`) and normal memory operations to maintain a list of shared libraries.
Still a special library list provided by this packet is more efficient for the
GDB remote protocol.

The ‘`qXfer:libraries-svr4:read`’ packet returns an XML document which lists
loaded libraries and their SVR4 linker parameters. For each library on SVR4
target, the following parameters are reported:

- - `name`, the absolute file name from the `l_name` field of `struct link_map`.
- - `lm` with address of `struct link_map` used for TLS (Thread Local Storage) access.
- - `l_addr`, the displacement as read from the field `l_addr` of `struct link_map`. For prelinked libraries this is not an absolute memory address. It is a displacement of absolute memory address against address the file was prelinked to during the library load.
- - `l_ld`, which is memory address of the `PT_DYNAMIC` segment
- - `lmid`, which is an identifier for a linker namespace, such as the memory address of the `r_debug` object that contains this namespace’s load map or the namespace identifier returned by `dlinfo (3)`.

Additionally the single `main-lm` attribute specifies address of `struct
link_map` used for the main executable. This parameter is used for TLS access
and its presence is optional.

GDB must be linked with the Expat library to support XML SVR4 library lists. See
[Expat](about:blank/Requirements.html#Expat).

A simple memory map, with two loaded libraries (which do not use prelink), looks
like this:

```
<library-list-svr4 version="1.0" main-lm="0xe4f8f8">
  <library name="/lib/ld-linux.so.2" lm="0xe4f51c" l_addr="0xe2d000"
           l_ld="0xe4eefc" lmid="0xfffe0"/>
  <library name="/lib/libc.so.6" lm="0xe4fbe8" l_addr="0x154000"
           l_ld="0x152350" lmid="0xfffe0"/>
</library-list-svr>
```

The format of an SVR4 library list is described by this DTD:

```
<!-- library-list-svr4: Root element with versioning -->
<!ELEMENT library-list-svr4  (library)*>
<!ATTLIST library-list-svr4  version CDATA   #FIXED  "1.0">
<!ATTLIST library-list-svr4  main-lm CDATA   #IMPLIED>
<!ELEMENT library            EMPTY>
<!ATTLIST library            name    CDATA   #REQUIRED>
<!ATTLIST library            lm      CDATA   #REQUIRED>
<!ATTLIST library            l_addr  CDATA   #REQUIRED>
<!ATTLIST library            l_ld    CDATA   #REQUIRED>
<!ATTLIST library            lmid    CDATA   #IMPLIED>
```

---