import gdbstub_cpp;
import core.thread : Thread;
import core.time : dur;
import std.algorithm : min;
import std.conv : to;
import std.getopt : getopt;
import std.stdio;
import std.string : toLower;
import std.typecons : Nullable, nullable;

enum IntegrationMode {
    blocking,
    polling,
    async,
}

class DlangTarget {
    enum regSizeBytes = 4;
    enum regCount = 8;
    enum memSize = 256;
    enum memBase = 0x1000;

    private IntegrationMode mode;
    private StopNotifier notifier;
    private bool running;
    private size_t pollTicks;
    private ulong currentThreadId = 1;

    private size_t breakpointsSet;
    private size_t breakpointsRemoved;

    ubyte[regSizeBytes * regCount] regs;
    ubyte[memSize] mem;
    ulong[] threads = [1, 2];

    this(IntegrationMode mode) {
        this.mode = mode;
        regs[] = 0;
        writeRegValue(1, 0x11223344);
        writeRegValue(regCount - 1, memBase);
        foreach (i; 0 .. mem.length) {
            mem[i] = cast(ubyte)(i & 0xff);
        }
    }

    private void writeRegValue(int regno, uint value) {
        auto base = cast(size_t)(regno * regSizeBytes);
        regs[base + 0] = cast(ubyte)(value & 0xff);
        regs[base + 1] = cast(ubyte)((value >> 8) & 0xff);
        regs[base + 2] = cast(ubyte)((value >> 16) & 0xff);
        regs[base + 3] = cast(ubyte)((value >> 24) & 0xff);
    }

    Target buildTarget() {
        auto builder = TargetBuilder()
            .withRegs(&regSize, &readReg, &writeReg)
            .withMem(&readMem, &writeMem)
            .withRun(
                &resume,
                &interrupt,
                mode == IntegrationMode.polling ? &pollStop : null,
                mode == IntegrationMode.async ? &setStopNotifier : null
            )
            .withMemoryLayout(&regionInfo, &memoryMap)
            .withHostInfo(&hostInfo)
            .withProcessInfo(&processInfo)
            .withShlibInfo(&shlibInfo)
            .withRegisterInfo(&registerInfo)
            .withBreakpoints(&setBreakpoint, &removeBreakpoint)
            .withThreads(
                &threadIds,
                &currentThread,
                &setCurrentThread,
                &threadPc,
                &threadName,
                &threadStopReason
            );
        return builder.build();
    }

    size_t regSize(int regno) {
        return regSizeBytes;
    }

    TargetStatus readReg(int regno, ubyte[] buffer) {
        auto offset = cast(size_t)(regno * regSizeBytes);
        if (offset + buffer.length > regs.length) {
            return TargetStatus.invalid;
        }
        buffer[] = regs[offset .. offset + buffer.length];
        return TargetStatus.ok;
    }

    TargetStatus writeReg(int regno, const(ubyte)[] data) {
        auto offset = cast(size_t)(regno * regSizeBytes);
        if (offset + data.length > regs.length) {
            return TargetStatus.invalid;
        }
        regs[offset .. offset + data.length] = data[];
        return TargetStatus.ok;
    }

    TargetStatus readMem(ulong addr, ubyte[] buffer) {
        if (addr < memBase) {
            return TargetStatus.fault;
        }
        auto start = cast(size_t)(addr - memBase);
        if (start >= mem.length) {
            return TargetStatus.fault;
        }
        auto count = min(buffer.length, mem.length - start);
        buffer[] = 0;
        buffer[0 .. count] = mem[start .. start + count];
        return TargetStatus.ok;
    }

    TargetStatus writeMem(ulong addr, const(ubyte)[] data) {
        if (addr < memBase) {
            return TargetStatus.fault;
        }
        auto start = cast(size_t)(addr - memBase);
        if (start >= mem.length) {
            return TargetStatus.fault;
        }
        auto count = min(data.length, mem.length - start);
        mem[start .. start + count] = data[0 .. count];
        return TargetStatus.ok;
    }

    ResumeResult resume(ResumeRequest request) {
        running = true;
        pollTicks = 0;
        if (mode == IntegrationMode.blocking) {
            return stoppedResult();
        }
        if (mode == IntegrationMode.async && notifier.isValid()) {
            auto notifyCopy = notifier;
            auto stopReason = stoppedReason();
            auto worker = new Thread(() {
                Thread.sleep(dur!"msecs"(100));
                notifyCopy.notify(stopReason);
            });
            worker.start();
        }
        ResumeResult result;
        result.state = ResumeState.running;
        return result;
    }

    void interrupt() {
        running = false;
    }

    Nullable!StopReason pollStop() {
        if (!running) {
            return Nullable!StopReason.init;
        }
        pollTicks++;
        if (pollTicks < 2) {
            return Nullable!StopReason.init;
        }
        running = false;
        return nullable(stoppedReason());
    }

    void setStopNotifier(StopNotifier notifier) {
        this.notifier = notifier;
    }

    MemoryRegion[] memoryMap() {
        MemoryRegion region;
        region.start = memBase;
        region.size = mem.length;
        region.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        region.name = nullable("ram");
        region.types = ["ram"];
        return [region];
    }

    Nullable!MemoryRegionInfo regionInfo(ulong addr) {
        if (addr < memBase || addr >= memBase + mem.length) {
            return Nullable!MemoryRegionInfo.init;
        }
        MemoryRegionInfo info;
        info.start = memBase;
        info.size = mem.length;
        info.mapped = true;
        info.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        info.name = nullable("ram");
        info.types = ["ram"];
        return nullable(info);
    }

    Nullable!HostInfo hostInfo() {
        HostInfo info;
        info.triple = "riscv32-unknown-elf";
        info.endian = "little";
        info.ptrSize = 4;
        info.hostname = "d-e2e";
        info.osVersion = nullable("1.0");
        info.osBuild = nullable("e2e");
        info.osKernel = nullable("e2e-kernel");
        info.addressingBits = nullable(32);
        return nullable(info);
    }

    Nullable!ProcessInfo processInfo() {
        ProcessInfo info;
        info.pid = 1234;
        info.triple = "riscv32-unknown-elf";
        info.endian = "little";
        info.ptrSize = 4;
        info.ostype = "bare";
        return nullable(info);
    }

    Nullable!ShlibInfo shlibInfo() {
        ShlibInfo info;
        info.infoAddr = nullable(0x11223344UL);
        return nullable(info);
    }

    Nullable!RegisterInfo registerInfo(int regno) {
        if (regno < 0 || regno >= regCount) {
            return Nullable!RegisterInfo.init;
        }

        RegisterInfo info;
        info.name = "r" ~ to!string(regno);
        info.bitsize = regSizeBytes * 8;
        info.offset = nullable(cast(size_t)(regno * regSizeBytes));
        info.encoding = "uint";
        info.format = "hex";

        if (regno == 0) {
            info.altName = nullable("zero");
            info.set = nullable("general");
            info.gccRegnum = nullable(0);
            info.dwarfRegnum = nullable(0);
            info.generic = nullable("arg1");
            info.containerRegs = [1, 2];
            info.invalidateRegs = [3];
        }

        return nullable(info);
    }

    TargetStatus setBreakpoint(BreakpointSpec spec) {
        breakpointsSet++;
        return TargetStatus.ok;
    }

    TargetStatus removeBreakpoint(BreakpointSpec spec) {
        breakpointsRemoved++;
        return TargetStatus.ok;
    }

    ulong[] threadIds() {
        return threads;
    }

    ulong currentThread() {
        return currentThreadId;
    }

    TargetStatus setCurrentThread(ulong tid) {
        currentThreadId = tid;
        return TargetStatus.ok;
    }

    Nullable!ulong threadPc(ulong tid) {
        return nullable(0x1000 + tid);
    }

    Nullable!string threadName(ulong tid) {
        return nullable("thread-" ~ to!string(tid));
    }

    Nullable!StopReason threadStopReason(ulong tid) {
        auto reason = stoppedReason();
        reason.threadId = nullable(tid);
        return nullable(reason);
    }

    private StopReason stoppedReason() {
        StopReason reason;
        reason.kind = StopKind.swBreak;
        reason.signal = 5; // SIGTRAP
        reason.threadId = nullable(currentThreadId);
        return reason;
    }

    private ResumeResult stoppedResult() {
        ResumeResult result;
        result.state = ResumeState.stopped;
        result.stop = stoppedReason();
        return result;
    }
}

IntegrationMode parseMode(string value) {
    auto lowered = value.toLower();
    if (lowered == "blocking") {
        return IntegrationMode.blocking;
    }
    if (lowered == "polling") {
        return IntegrationMode.polling;
    }
    if (lowered == "async") {
        return IntegrationMode.async;
    }
    throw new Exception("unknown mode: " ~ value);
}

void main(string[] args) {
    string listen = "127.0.0.1:5555";
    string modeStr = "async";

    getopt(args,
        "listen", &listen,
        "mode", &modeStr,
    );

    auto mode = parseMode(modeStr);
    auto targetImpl = new DlangTarget(mode);
    auto target = targetImpl.buildTarget();

    ArchSpec arch;
    arch.targetXml = "<target version=\"1.0\"><architecture>riscv:rv32</architecture></target>";
    arch.xmlArchName = "riscv";
    arch.regCount = DlangTarget.regCount;
    arch.pcRegNum = DlangTarget.regCount - 1;
    arch.osabi = "bare";

    auto transport = new TransportTcp();
    auto server = new Server(target, arch, transport);

    if (!server.listen(listen)) {
        writeln("listen failed: ", listen);
        stdout.flush();
        return;
    }

    writeln("waiting for debugger on ", listen, " (mode=", modeStr, ")");
    stdout.flush();
    if (mode == IntegrationMode.blocking) {
        server.serveForever();
        return;
    }

    if (!server.waitForConnection()) {
        writeln("connection failed");
        stdout.flush();
        return;
    }

    while (server.hasConnection()) {
        server.poll(10);
    }
}
