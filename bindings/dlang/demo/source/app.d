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

class DemoTarget {
    enum regSizeBytes = 4;
    enum regCount = 16;

    private IntegrationMode mode;
    private StopNotifier notifier;
    private bool running;
    private size_t pollTicks;

    ubyte[regSizeBytes * regCount] regs;
    ubyte[512] mem;

    this(IntegrationMode mode) {
        this.mode = mode;
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
            .withMemoryLayout(&regionInfo, &memoryMap);
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
        auto start = cast(size_t)addr;
        if (start >= mem.length) {
            return TargetStatus.fault;
        }
        auto count = min(buffer.length, mem.length - start);
        buffer[0 .. count] = mem[start .. start + count];
        return TargetStatus.ok;
    }

    TargetStatus writeMem(ulong addr, const(ubyte)[] data) {
        auto start = cast(size_t)addr;
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
                Thread.sleep(dur!"msecs"(200));
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
        if (pollTicks < 3) {
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
        region.start = 0;
        region.size = mem.length;
        region.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        region.name = nullable("ram");
        region.types = ["ram"];
        return [region];
    }

    Nullable!MemoryRegionInfo regionInfo(ulong addr) {
        if (addr >= mem.length) {
            return Nullable!MemoryRegionInfo.init;
        }
        MemoryRegionInfo info;
        info.start = 0;
        info.size = mem.length;
        info.mapped = true;
        info.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        info.name = nullable("ram");
        info.types = ["ram"];
        return nullable(info);
    }

    private StopReason stoppedReason() {
        StopReason reason;
        reason.kind = StopKind.signal;
        reason.signal = 5; // SIGTRAP
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
    auto targetImpl = new DemoTarget(mode);
    auto target = targetImpl.buildTarget();

    ArchSpec arch;
    arch.regCount = DemoTarget.regCount;
    arch.pcRegNum = DemoTarget.regCount - 1;
    arch.osabi = "bare";

    auto transport = new TransportTcp();
    auto server = new Server(target, arch, transport);

    if (!server.listen(listen)) {
        writeln("listen failed: ", listen);
        return;
    }

    writeln("waiting for debugger on ", listen, " (mode=", modeStr, ")");
    if (!server.waitForConnection()) {
        writeln("connection failed");
        return;
    }

    if (mode == IntegrationMode.blocking) {
        server.serveForever();
        return;
    }

    while (server.hasConnection()) {
        server.poll(10);
    }
}
