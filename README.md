# r2-symbol-importer

AST-based C symbol, struct, function signature, and IOCTL/constant extractor and importer for **radare2** and **iaito**.

When analyzing binaries without debug symbols or PDBs—such as Windows drivers, Linux kernel modules, embedded firmware, network daemons, or userland shared libraries—disassemblers lack structure layouts, field offsets, function parameter types, and readable constant names. 

`r2-symbol-importer` parses C headers directly using Tree-sitter, sanitizes compiler-specific syntax (MSVC/GCC attributes, calling conventions, Microsoft SAL annotations), safely evaluates preprocessor expressions and bitmasks (including Windows `CTL_CODE` IOCTLs), and injects the extracted types, signatures, and flags into an active radare2 or iaito session.

---

## Features

- **Tree-sitter AST Extraction:** Accurately parses C structs, unions, enums, typedefs, and function prototypes directly from headers without requiring a compiler toolchain.
- **Syntax Sanitization:** Strips nested GCC attributes (`__attribute__((...))`), MSVC specifiers (`__declspec(...)`), inline assembly, calling conventions (`__stdcall`, `NTAPI`, `FASTCALL`), and Microsoft SAL annotations (`_In_`, `_Out_`, `_Must_inspect_result_`).
- **Safe Constant & IOCTL Evaluation:** Evaluates arithmetic, bitwise shifts (`1 << 4`), bitmasks, and Windows `CTL_CODE(...)` macro definitions into hexadecimal flag values (`f const.<name> = <val>`) using safe Python AST evaluation without arbitrary code execution.
- **Topological Dependency Sorting:** Re-orders nested struct, union, and typedef declarations so radare2's C parser (`to`) compiles them without undeclared identifier errors.
- **Built-in Type Preludes:** Includes preset type definitions (`windows`, `posix`, and fixed-width `stdint`) to satisfy prerequisite primitive types (`DWORD`, `PVOID`, `HANDLE`, `NTSTATUS`, `size_t`, `intptr_t`).
- **radare2 In-Session Integration:** Runs directly inside an active radare2 prompt via `#!pipe`.
- **iaito Native Menu & GUI Plugin:** Native Qt dialog (supporting PySide6, PyQt6, PySide2, and PyQt5) with file/directory browsing, preview tabs for extracted types/signatures/flags, and 1-click native menu bar integration (`Tools` &rarr; `Import C Symbols & Headers...`).

---

## Installation

### Dependencies

- Python 3.9+
- radare2 (5.8.0+)
- Python packages: `r2pipe`, `tree-sitter`, `tree-sitter-c` (or `tree-sitter-language-pack`)
- Optional GUI dependency: `PySide6` (or `PyQt6` / `PyQt5`)

### Install via pip

```bash
pip install .
```

To include GUI and test dependencies:

```bash
pip install ".[all]"
```

---

## Usage

### 1. In radare2 (In-Session)

Run the importer inside an active radare2 session using `#!pipe`:

```text
[0x00000000]> #!pipe python3 -m r2_symbol_importer /path/to/header.h
```

Or using the installed CLI entrypoint:

```text
[0x00000000]> #!pipe r2-symbol-importer /path/to/include_dir/
```

#### Command-Line Options

```text
usage: r2-symbol-importer [-h] [--install-iaito] [--no-types] [--no-protos]
                          [--no-flags] [--prelude {auto,windows,posix,stdint,none}]
                          [--dry-run] [-o FILE.r2] [--json]
                          [target]

positional arguments:
  target                Path to C header file (.h, .i) or include directory.

options:
  --install-iaito       Install bootstrap loader into iaito user plugins directory.
  --no-types            Skip C struct, union, enum, and typedef import ('to').
  --no-protos           Skip function prototypes / signatures import ('afs').
  --no-flags            Skip #define constants and IOCTL flags import ('f const.*').
  --prelude PRELUDE     Type prelude preset (auto, windows, posix, stdint, none). Default: auto.
  --dry-run             Print radare2 commands and header preview without applying.
  -o, --output-script   Export generated radare2 commands to a standalone .r2 script file.
  --json                Output result summary in JSON format.
```

#### Verifying Loaded Symbols in radare2

- **List Loaded Structs:**
  ```text
  [0x00000000]> ts
  ```
- **Inspect Struct Field Offsets & Layout:**
  ```text
  [0x00000000]> ts PACKET_HEADER
  ```
- **List Loaded Typedefs:**
  ```text
  [0x00000000]> tt
  ```
- **List Imported Constants & IOCTL Flags:**
  ```text
  [0x00000000]> f~const.
  ```
- **Check Function Signatures in Disassembly:**
  ```text
  [0x00000000]> pdf @ sym.DriverEntry
  ```

---

### 2. In iaito (GUI)

#### Option A: Native Menu Integration (Recommended)

Install the plugin loader into iaito once:

```bash
r2-symbol-importer --install-iaito
```

When you launch iaito, the menu action **Import C Symbols & Headers...** will automatically appear under the **Tools** (or **Plugins**) menu. Clicking it opens the importer dialog connected directly to the open session.

#### Option B: From iaito's Embedded Python Console

If you prefer to attach the menu or launch the dialog on-demand:

1. Open iaito and load your target binary.
2. Open the embedded Python Console (**View** &rarr; **Python Console**).
3. Add the menu item to the running window:
   ```python
   import r2_symbol_importer.iaito_plugin as ip
   ip.install_menu()
   ```
   Or launch the dialog directly:
   ```python
   ip.launch()
   ```
4. In the dialog:
   - Select a single `.h`/`.i` file or an include folder.
   - Choose your prelude preset (or leave on **Auto-detect**).
   - Click **Preview Extraction** to inspect extracted types, signatures, and constants in dedicated tabs.
   - Click **Import Symbols into radare2** to apply the definitions to your live iaito session.

---

### 3. Generating Standalone `.r2` Scripts

To generate a script that can be committed or shared without running Python during analysis:

```bash
python3 -m r2_symbol_importer path/to/header.h -o import_symbols.r2 --dry-run
```

In radare2:

```text
[0x00000000]> . import_symbols.r2
```

---

## Architecture & Project Structure

```text
r2_symbol_importer/
├── __init__.py
├── __main__.py              # python3 -m r2_symbol_importer entrypoint
├── r2_plugin.py             # radare2 in-session CLI / r2pipe plugin & --install-iaito
├── iaito_plugin.py          # iaito Qt GUI dialog & menu bar integration
├── qt_compat.py             # Transparent PySide6/PyQt6/PySide2/PyQt5 fallback shim
└── core/
    ├── __init__.py
    ├── parser.py            # Tree-sitter C parser and attribute sanitizer
    ├── constants.py         # AST safe evaluator for constants, bitwise ops, CTL_CODE
    ├── preludes.py          # Windows DDK, POSIX, and stdint C type preludes
    ├── sorter.py            # Topological type dependency resolver
    └── pipeline.py          # Ingestion pipeline orchestrator
tests/
├── conftest.py
├── fixtures/
│   ├── sample_driver.h      # Windows Kernel DDK test header with IOCTLs and SAL
│   ├── sample_posix.h       # POSIX driver header with bitfields and enums
│   └── sample_binary.c      # C test binary fixture
├── test_parser.py           # AST extraction & sanitization tests
├── test_constants.py        # Expression and IOCTL computation tests
├── test_sorter.py           # Topological sorting tests
├── test_r2_integration.py   # Live r2pipe session verification tests
├── test_generic_headers.py  # Network protocol, embedded register map, userland tests
├── test_iaito_gui.py        # Headless Qt GUI dialog tests
└── test_iaito_menu.py       # iaito menu bar injection & loader installer tests
```

---

## Testing

### Running Tests Locally

```bash
pip install -e ".[all]"
pytest -v
```

### Running Tests in Official radare2 Podman Container

```bash
podman run --rm -it \
  -v "$(pwd)":/workspace:Z \
  -w /workspace \
  docker.io/radare/radare2:latest \
  bash -c "apt-get update && apt-get install -y python3-pip && pip3 install -e '.[test]' --break-system-packages && pytest -v"
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
