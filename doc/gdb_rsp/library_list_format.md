# Library List Format (Debugging with GDB)

---

### E.15 Library List Format

On some platforms, a dynamic loader (e.g. `ld.so`) runs in the same process as
your application to manage libraries. In this case, GDB can use the loader’s
symbol table and normal memory operations to maintain a list of shared
libraries. On other platforms, the operating system manages loaded libraries.
GDB can not retrieve the list of currently loaded libraries through memory
operations, so it uses the ‘`qXfer:libraries:read`’ packet (see [qXfer library
list read](about:blank/General-Query-Packets.html#qXfer-library-list-read))
instead. The remote stub queries the target’s operating system and reports which
libraries are loaded.

The ‘`qXfer:libraries:read`’ packet returns an XML document which lists loaded
libraries and their offsets. Each library has an associated name and one or more
segment or section base addresses, which report where the library was loaded in
memory.

For the common case of libraries that are fully linked binaries, the library
should have a list of segments. If the target supports dynamic linking of a
relocatable object file, its library XML element should instead include a list
of allocated sections. The segment or section bases are start addresses, not
relocation offsets; they do not depend on the library’s link-time base
addresses.

GDB must be linked with the Expat library to support XML library lists. See
[Expat](about:blank/Requirements.html#Expat).

A simple memory map, with one loaded library relocated by a single offset, looks
like this:

```
<library-list>
  <library name="/lib/libc.so.6">
    <segment address="0x10000000"/>
  </library>
</library-list>
```

Another simple memory map, with one loaded library with three allocated sections
(.text, .data, .bss), looks like this:

```
<library-list>
  <library name="sharedlib.o">
    <section address="0x10000000"/>
    <section address="0x20000000"/>
    <section address="0x30000000"/>
  </library>
</library-list>
```

The format of a library list is described by this DTD:

```
<!-- library-list: Root element with versioning -->
<!ELEMENT library-list  (library)*>
<!ATTLIST library-list  version CDATA   #FIXED  "1.0">
<!ELEMENT library       (segment*, section*)>
<!ATTLIST library       name    CDATA   #REQUIRED>
<!ELEMENT segment       EMPTY>
<!ATTLIST segment       address CDATA   #REQUIRED>
<!ELEMENT section       EMPTY>
<!ATTLIST section       address CDATA   #REQUIRED>
```

In addition, segments and section descriptors cannot be mixed within a single
library element, and you must supply at least one segment or section for each
library.

---