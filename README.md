# gdbstub_cpp

a modern gdbstub library

## troubleshooting

run lldb with debug packets
```sh
lldb --no-lldbinit -o "log enable gdb-remote packets" -o "gdb-remote 127.0.0.1:23666"
```
