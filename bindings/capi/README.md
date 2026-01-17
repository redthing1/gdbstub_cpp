# gdbstub_cpp C ABI

This is a small C ABI shim over the C++ gdbstub_cpp core.
It is intended to be a stable, reusable base for language bindings.

The shim is built by the main CMake project as the `gdbstub_c` static library.

- Headers: `bindings/capi/include`
- Sources: `bindings/capi/src`
