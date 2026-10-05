import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class ReaDolImport extends HeadlessScript {
    private record Section(int index, long offset, long address, long size) {}

    private long u32(ByteBuffer header, int offset) {
        return Integer.toUnsignedLong(header.getInt(offset));
    }

    private boolean containsEntry(List<Section> sections, long entry) {
        return sections.stream().anyMatch(s -> s.index() < 7 &&
            entry >= s.address() && entry < s.address() + s.size());
    }

    @Override
    protected void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);
        Memory memory = currentProgram.getMemory();
        List<FileBytes> files = memory.getAllFileBytes();
        if (files.size() != 1 || files.get(0).getSize() < 0x100)
            throw new IllegalArgumentException("DOL requires one complete input file");
        FileBytes file = files.get(0);
        byte[] bytes = new byte[0x100];
        file.getOriginalBytes(0, bytes);
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        List<Section> sections = new ArrayList<>();
        for (int i = 0; i < 18; i++) {
            long offset = u32(header, i * 4);
            long address = u32(header, 0x48 + i * 4);
            long size = u32(header, 0x90 + i * 4);
            if (size == 0) continue;
            if (offset < 0x100 || offset + size > file.getSize() ||
                    address + size > 0x100000000L)
                throw new IllegalArgumentException("Invalid DOL section bounds");
            for (Section s : sections) {
                if ((offset < s.offset() + s.size() && s.offset() < offset + size) ||
                        (address < s.address() + s.size() && s.address() < address + size))
                    throw new IllegalArgumentException("Overlapping DOL sections");
            }
            sections.add(new Section(i, offset, address, size));
        }
        long entry = u32(header, 0xe0);
        if (!containsEntry(sections, entry) && entry < 0x01800000L)
            entry += 0x80000000L;
        if (entry % 4 != 0 || !containsEntry(sections, entry))
            throw new IllegalArgumentException("Invalid DOL entry point");
        long bssStart = u32(header, 0xd8);
        long bssEnd = bssStart + u32(header, 0xdc);
        if (bssEnd > 0x100000000L)
            throw new IllegalArgumentException("Invalid DOL BSS bounds");
        for (MemoryBlock block : memory.getBlocks()) memory.removeBlock(block, monitor);
        for (Section s : sections) {
            boolean executable = s.index() < 7;
            String name = executable ? ".text" + s.index() : ".data" + (s.index() - 7);
            MemoryBlock block = memory.createInitializedBlock(name, toAddr(s.address()),
                file, s.offset(), s.size(), false);
            block.setRead(true);
            block.setWrite(!executable);
            block.setExecute(executable);
        }
        sections.sort(Comparator.comparingLong(Section::address));
        int index = 0;
        for (Section s : sections) {
            if (s.address() >= bssEnd) break;
            if (s.address() + s.size() <= bssStart) continue;
            if (s.address() > bssStart)
                createBss(memory, index++, bssStart, s.address() - bssStart);
            bssStart = Math.max(bssStart, s.address() + s.size());
        }
        if (bssStart < bssEnd) createBss(memory, index, bssStart, bssEnd - bssStart);
        currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
        createLabel(toAddr(entry), "_start", true, SourceType.IMPORTED);
        disassemble(toAddr(entry));
        createFunction(toAddr(entry), "_start");
        currentProgram.getOptions("Program Information").setString("REA DOL importer", "rea-dol-v1");
        setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
    }

    private void createBss(Memory memory, int index, long address, long size) throws Exception {
        MemoryBlock block = memory.createUninitializedBlock(".bss" + index, toAddr(address), size, false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
    }
}
