# gdbstub_cpp d bindings

d bindings for gdbstub_cpp built on a small c abi shim.

## requirements

- cmake
- c++20 toolchain

## usage

add the package as a path dependency:

```
dependency "gdbstub_cpp" path "path/to/gdbstub_cpp/bindings/dlang/gdbstub_cpp-d"
```

then import the module:

```
import gdbstub_cpp;
```

minimal target setup:

```
auto target = TargetBuilder()
    .withRegs(&regSize, &readReg, &writeReg)
    .withMem(&readMem, &writeMem)
    .withRun(&resume, &interrupt, &pollStop, &setStopNotifier)
    .build();
```

## demo

```
dub run --root ../demo -- --mode async --listen 127.0.0.1:5555
```

supported modes: `blocking`, `polling`, `async`.

## tests

```
dub test
```

## end-to-end (lldb)

```
python3 test/gdbstub/lldb_e2e_dlang_test.py --lldb /path/to/lldb
```
