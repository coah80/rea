# Wii PowerPC support

This branch adds big-endian ELF32 PowerPC and Nintendo DOL input to REA's Ghidra provider. It uses the Gekko/Broadway language from [Ghidra-GameCube-Loader](https://github.com/Cuyler36/Ghidra-GameCube-Loader/tree/921504c9ddba6e8d9b3655b665a60f1a33306220), including paired-single instructions. Hopper and the Windows Ghidra provider do not support this path.

## Setup

Use a separate Ghidra 12.1.4 installation and a full JDK 21. Install the language once:

```sh
git clone https://github.com/Cuyler36/Ghidra-GameCube-Loader.git /path/to/gamecube-loader
git -C /path/to/gamecube-loader checkout 921504c9ddba6e8d9b3655b665a60f1a33306220
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/path/to/jdk-21
node scripts/install-wii-language.mjs "$GHIDRA_INSTALL_DIR" /path/to/gamecube-loader
npm ci --ignore-scripts
./node_modules/.bin/tsc -p tsconfig.build.json
```

The installer refuses to overwrite an existing module. It copies only the language and its license, then compiles it with Ghidra's SLEIGH compiler. REA hashes the compiled language and its specifications into the analysis profile.

## Analyze

```sh
node scripts/rea.mjs analyze /path/to/main.elf --provider ghidra --json
node scripts/rea.mjs analyze /path/to/main.dol --provider ghidra --json
node scripts/verify-wii-powerpc.mjs /path/to/main.elf PSMTXIdentity
node scripts/verify-wii-powerpc.mjs /path/to/main.dol 0x80003400
```

The verifier checks target classification, authenticated Ghidra startup, assembly, and pseudocode. It saves the provider session, section inventory, procedure inventory, and decompiled function under `build/wii-verification`.

The DOL importer validates section bounds and overlaps, maps text and data at their declared addresses, creates BSS only outside initialized sections, and resolves a physical MEM1 entry address to its mapped cached alias. It preserves the original file digest. A failed DOL import cannot serve raw-binary results through the bridge.

The Wii Menu 4.3U DOL wraps its main program in a data section and has a small bootstrap text section. The importer preserves that layout. Use the corresponding `main.elf` for symbol-based analysis of the main program; importing the wrapper does not reconstruct its runtime memory changes.

REA output is decompiler analysis. Exact source matching and full linking still require the Wii project's object comparison and DOL checks.

## This machine

The configured command is `/mnt/drive2/tools/rea-wii/rea`. It uses this checkout and the separate Ghidra installation under `/mnt/drive2/tools/rea-wii`.

```sh
/mnt/drive2/tools/rea-wii/rea analyze /mnt/drive2/projects/wiichannels/wii-ipl/build/43U/main.elf --provider ghidra --json
```

Live verification imported both Wii Menu files and recovered assembly and pseudocode. The ELF inventory contains 12,604 functions. `PSMTXIdentity` decoded with `psq_st` and `ps_merge` instructions. A synthetic DOL also verified paired-single decoding and BSS split around initialized data. Results are saved in `build/wii-verification`.
