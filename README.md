# Sig Scanner - Binary Ninja Plugin

A sidebar plugin for Binary Ninja that provides IDA-style byte pattern signature scanning and generation.

## Features

### Signature Scanning
- IDA-style byte pattern scanning with wildcard support (`?` and `??`)
- Auto-strips non-hex junk from pasted signatures (paste directly from IDA/x64dbg)
- Scan history — remembers your last 10 signatures
- Scan executable segments only or all segments
- Results table with: **Address**, **RVA**, **Section**, **Function**, **Instruction**
- Right-click results to navigate, copy address/RVA/function name

### Signature Generation
- Generate signatures from any address or selected code range
- Auto-wildcards operand bytes for instructions with relocations/references
- **[Marked] bytes** — mark important wildcards with `[? ? ? ?]` so external tools know which bytes matter (e.g. pointer to a global variable)
- Click instructions to cycle: **Fixed** → **Wildcard** → **[Marked]** → **Fixed**
- Available from right-click context menu in disassembly and pseudo-C views

## Installation

Copy the `sigscanner` folder to your Binary Ninja plugins directory:

- **Windows:** `%APPDATA%\Binary Ninja\plugins\`
- **macOS:** `~/Library/Application Support/Binary Ninja/plugins/`
- **Linux:** `~/.binaryninja/plugins/`

## Usage

### Scanning
1. Open the **Sig Scanner** sidebar (magnifying glass icon on the left)
2. Paste or type a signature: `48 89 5C 24 ?? 48 89 74 24 ??`
3. Press **Enter** or click **Scan**
4. Click any result to navigate, right-click for more options

### Generating Signatures
1. Right-click in disassembly → **Sig Scanner** → **Generate Signature at Address**
2. Or select a range → right-click → **Sig Scanner** → **Generate Signature from Selection**
3. In the generator dialog, click instructions to toggle wildcard/marked state
4. Click **Copy Signature** to copy the result

### Marked Bytes
Use `[? ? ? ?]` to mark bytes that are important for your external tools:

```
48 89 7C 24 ? E8 ? ? ? ? 48 8B 05 [? ? ? ?] 45 33 C0
```

The `[...]` tells your parser which wildcard bytes contain the offset/pointer you need to resolve.

## License

MIT License - Copyright (c) 2026 S1ckZer

See [LICENSE](LICENSE) for details.
