# Tendermint Log Analyzer

The Tendermint Log Analyzer is a powerful tool for analyzing and categorizing Tendermint/Cosmos SDK node logs in both JSON and plain text formats. Designed to efficiently process very large log files, the tool uses memory‐efficient techniques (mmap), multi‐threaded processing, and clear progress indicators. It offers both an interactive mode (with a rich, colorful menu) and a command‑line interface.

## Features

- **Dual Log Format Support:** Automatically handles both JSON-formatted and plain text log entries.
- **Pattern-based Log Grouping:** Groups logs by normalized message patterns (e.g. filtering out dynamic parts).
- **Multi-threaded Processing:** Uses a ThreadPoolExecutor to concurrently process file chunks.
- **Memory-efficient:** Leverages mmap so that large files are processed without loading the entire file into memory.
- **Module-based & Log Level Analysis:** Categorizes logs by module, log level, height, and time.
- **Custom Exclusion Patterns:** Supports user-defined regex filters to exclude unwanted log entries.
- **Progress Indicators:** Displays progress bars for reading the file, processing chunks (with an ETA based on an estimated number of chunks), and saving organized logs.
- **Output Organization:** Saves organized logs into clearly named subdirectories (time, level, module, height, and pattern) within the specified output directory.
- **Interactive and CLI Modes:** Use the interactive rich‑prompt menu when no command‑line arguments are provided, or run with full CLI options.

## Installation

Install the required dependencies using pip:

```bash
pip install -r requirements.txt
```

The **requirements.txt** should contain:

```txt
tqdm>=4.65.0
rich>=13.0.0
```

## Log Format Support

### JSON Format
```json
{"level": "info", "module": "state", "height": 129505798, "time": "2025-02-02T22:01:53Z", "message": "committed state"}
```

### Text Format
```
3:05PM DBG Received bytes chID=32 module=p2p msgBytes="..."
```

## Usage

Run the analyzer via command line:

```bash
python tendermint_logs.py [OPTIONS]
```

### Interactive Mode

If no input or output paths are provided via command-line arguments, the script launches an interactive menu (powered by Rich) where you can:
- **Analyze File:** Process and categorize the log file.
- **View Summary:** See statistics such as total log entries, unique patterns, log level counts, top modules, and height ranges.
- **Explore Patterns:** Browse, search, and filter log patterns.
- **Add Exclusion Pattern:** Dynamically add regex filters to exclude unwanted log entries.
- **Save Organized Logs:** Export the processed logs into organized subdirectories.
- **Exit**

### Command-Line Options

- `--input`, `-i`: Path to the input log file.
- `--output`, `-o`: Path to the output directory.
- `--exclude`, `-e`: Exclusion regex pattern (can be used multiple times).
- `--verbose`, `-v`: Enable verbose (debug) output.

#### Example

```bash
python tendermint_logs.py --input ./sei_node.log --output ./organized_logs --exclude 'DEBUG|debug' --verbose
```

## Output Organization

When saving the results, the logs are exported into subdirectories within your specified output directory:

- **Time-based logs:** Located in the `time` subdirectory.
- **Level-based logs:** Located in the `level` subdirectory.
- **Module-based logs:** Located in the `module` subdirectory.
- **Height-based logs:** Located in the `height` subdirectory.
- **Pattern-based logs:** Located in the `pattern` subdirectory.

This subdirectory organization keeps your output folder uncluttered and makes it easier to locate the logs you need.

## Requirements

- Python 3.7+
- [tqdm](https://github.com/tqdm/tqdm) (>= 4.65.0)
- [rich](https://github.com/Textualize/rich) (>= 13.0.0)
