# Target Description Format (Debugging with GDB)

---

### G.2 Target Description Format

A target description annex is an [XML](http://www.w3.org/XML/) document which
complies with the Document Type Definition provided in the GDB sources in
`gdb/features/gdb-target.dtd`. This means you can use generally available tools
like `xmllint` to check that your feature descriptions are well-formed and
valid. However, to help people unfamiliar with XML write descriptions for their
targets, we also describe the grammar here.

Target descriptions can identify the architecture of the remote target and (for
some architectures) provide information about custom register sets. They can
also identify the OS ABI of the remote target. GDB can use this information to
autoconfigure for your target, or to warn you if you connect to an unsupported
target.

Here is a simple target description:

```
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>

```

This minimal description only says that the target uses the x86-64 architecture.

A target description has the following overall form, with [ ] marking optional
elements and … marking repeatable elements. The elements are explained further
below.

```
<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  [architecture]
  [osabi]
  [compatible]
  [feature…]
</target>

```

The description is generally insensitive to whitespace and line breaks, under
the usual common-sense rules. The XML version declaration and document type
declaration can generally be omitted (GDB does not require them), but specifying
them may be useful for XML validation tools. The ‘`version`’ attribute for
‘`<target>`’ may also be omitted, but we recommend including it; if future
versions of GDB use an incompatible revision of `gdb-target.dtd`, they will
detect and report the version mismatch.

#### G.2.1 Inclusion

It can sometimes be valuable to split a target description up into several
different annexes, either for organizational purposes, or to share files between
different possible target descriptions. You can divide a description into
multiple files by replacing any element of the target description with an
inclusion directive of the form:

```
<xi:include href="document"/>

```

When GDB encounters an element of this form, it will retrieve the named XML
document, and replace the inclusion directive with the contents of that
document. If the current description was read using ‘`qXfer`’, then so will be
the included document; document will be interpreted as the name of an annex. If
the current description was read from a file, GDB will look for document as a
file in the same directory where it found the original description.

#### G.2.2 Architecture

An ‘`<architecture>`’ element has this form:

```
  <architecture>arch</architecture>

```

arch is one of the architectures from the set accepted by `set architecture`
(see [Specifying a Debugging Target](about:blank/Targets.html#Targets)).

#### G.2.3 OS ABI

This optional field was introduced in GDB version 7.0. Previous versions of GDB
ignore it.

An ‘`<osabi>`’ element has this form:

```
  <osabi>abi-name</osabi>

```

abi-name is an OS ABI name from the same selection accepted by `set osabi` (see
[Configuring the Current ABI](about:blank/ABI.html#ABI)).

#### G.2.4 Compatible Architecture

This optional field was introduced in GDB version 7.0. Previous versions of GDB
ignore it.

A ‘`<compatible>`’ element has this form:

```
  <compatible>arch</compatible>

```

arch is one of the architectures from the set accepted by `set architecture`
(see [Specifying a Debugging Target](about:blank/Targets.html#Targets)).

A ‘`<compatible>`’ element is used to specify that the target is able to run
binaries in some other than the main target architecture given by the
‘`<architecture>`’ element. For example, on the Cell Broadband Engine, the main
architecture is `powerpc:common` or `powerpc:common64`, but the system is able
to run binaries in the `spu` architecture as well. The way to describe this
capability with ‘`<compatible>`’ is as follows:

```
  <architecture>powerpc:common</architecture>
  <compatible>spu</compatible>

```

#### G.2.5 Features

Each ‘`<feature>`’ describes some logical portion of the target system. Features
are currently used to describe available CPU registers and the types of their
contents. A ‘`<feature>`’ element has this form:

```
<feature name="name">
  [type…]
  reg…
</feature>

```

Each feature’s name should be unique within the description. The name of a
feature does not matter unless GDB has some special knowledge of the contents of
that feature; if it does, the feature should have its standard name. See
[Standard Target
Features](about:blank/Standard-Target-Features.html#Standard-Target-Features).

#### G.2.6 Types

Any register’s value is a collection of bits which GDB must interpret. The
default interpretation is a two’s complement integer, but other types can be
requested by name in the register description. Some predefined types are
provided by GDB (see [Predefined Target
Types](about:blank/Predefined-Target-Types.html#Predefined-Target-Types)), and
the description can define additional composite and enum types.

Each type element must have an ‘`id`’ attribute, which gives a unique (within
the containing ‘`<feature>`’) name to the type. Types must be defined before
they are used.

Some targets offer vector registers, which can be treated as arrays of scalar
elements. These types are written as ‘`<vector>`’ elements, specifying the array
element type, type, and the number of elements, count:

```
<vector id="id" type="type" count="count"/>

```

If a register’s value is usefully viewed in multiple ways, define it with a
union type containing the useful representations. The ‘`<union>`’ element
contains one or more ‘`<field>`’ elements, each of which has a name and a type:

```
<union id="id">
  <field name="name" type="type"/>
  …
</union>

```

If a register’s value is composed from several separate values, define it with
either a structure type or a flags type. A flags type may only contain
bitfields. A structure type may either contain only bitfields or contain no
bitfields. If the value contains only bitfields, its total size in bytes must be
specified.

Non-bitfield values have a name and type.

```
<struct id="id">
  <field name="name" type="type"/>
  …
</struct>

```

Both name and type values are required. No implicit padding is added.

Bitfield values have a name, start, end and type.

```
<struct id="id" size="size">
  <field name="name" start="start" end="end" type="type"/>
  …
</struct>

```

```
<flags id="id" size="size">
  <field name="name" start="start" end="end" type="type"/>
  …
</flags>

```

The name value is required. Bitfield values may be named with the empty string,
‘`""`’, in which case the field is “filler” and its value is not printed. Not
all bits need to be specified, so “filler” fields are optional.

The start and end values are required, and type is optional. The field’s start
must be less than or equal to its end, and zero represents the least significant
bit.

The default value of type is `bool` for single bit fields, and an unsigned
integer otherwise.

Which to choose? Structures or flags?

Registers defined with ‘`flags`’ have these advantages over defining them with
‘`struct`’:

- Arithmetic may be performed on them as if they were integers.
- They are printed in a more readable fashion.

Registers defined with ‘`struct`’ have one advantage over defining them with
‘`flags`’:

- One can fetch individual fields like in ‘`C`’.

  ```
  (gdb) print $my_struct_reg.field3
  $1 = 42

  ```

#### G.2.7 Registers

Each register is represented as an element with this form:

```
<reg name="name"
     bitsize="size"
     [regnum="num"]
     [save-restore="save-restore"]
     [type="type"]
     [group="group"]/>

```

The components are as follows:

name
:   The register’s name; it must be unique within the target description.

bitsize
:   The register’s size, in bits.

regnum
:   The register’s number. If omitted, a register’s number is one greater than that
    of the previous register (either in the current feature or in a preceding
    feature); the first register in the target description defaults to zero. This
    register number is used to read or write the register; e.g. it is used in the
    remote `p` and `P` packets, and registers appear in the `g` and `G` packets in
    order of increasing register number.

save-restore
:   Whether the register should be preserved across inferior function calls; this
    must be either `yes` or `no`. The default is `yes`, which is appropriate for
    most registers except for some system control registers; this is not related to
    the target’s ABI.

type
:   The type of the register. It may be a predefined type, a type defined in the
    current feature, or one of the special types `int` and `float`. `int` is an
    integer type of the correct size for bitsize, and `float` is a floating point
    type (in the architecture’s normal floating point format) of the correct size
    for bitsize. The default is `int`.

group
:   The register group to which this register belongs. It can be one of the standard
    register groups `general`, `float`, `vector` or an arbitrary string. Group names
    should be limited to alphanumeric characters. If a group name is made up of
    multiple words the words may be separated by hyphens; e.g. `special-group` or
    `ultra-special-group`. If no group is specified, GDB will not display the
    register in `info registers`.

---