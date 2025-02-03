# Tendermint Log Analyzer

Processes and categorizes Tendermint/Cosmos SDK node logs in JSON and plain text formats. Multithreaded for extremely large logfile handling, with ~~progress~~ pain indicators for file reading, processing, and saving.

## Features

- Supports JSON and plain text log formats
- Pattern-based grouping with dynamic part normalization
- Multi-threaded processing via ThreadPoolExecutor
- Memory efficient using mmap
- Categorizes logs by module, log level, time, and height
- Custom exclusion patterns using regex
- Progress indicators for all major stages
- Organized output in subdirectories

## Installation

Install dependencies with:

```bash
pip install -r requirements.txt
```

**requirements.txt:**

```txt
tqdm>=4.65.0
rich>=13.0.0
```

## Supported Log Formats

### JSON Format

```json
{"level": "info", "module": "state", "height": 129505798, "time": "2025-02-02T22:01:53Z", "message": "committed state"}
```

### Text Format

```
3:05PM DBG Received bytes chID=32 module=p2p msgBytes="..."
```

## Usage

### Interactive Mode

Run without arguments:

```bash
python tendermint_logs.py
```

Follow the menu to:
- Analyze the log file
- View summary statistics
- Explore log patterns
- Add exclusion filters
- Save organized logs

### Command-Line Mode

Options:
- `--input`, `-i`: Input log file path
- `--output`, `-o`: Output directory path
- `--exclude`, `-e`: Exclusion regex pattern (repeatable)
- `--verbose`, `-v`: Enable verbose logging

Example:

```bash
python tendermint_logs.py --input ./sei_node.log --output ./organized_logs --exclude 'DEBUG|debug' --verbose
```

## Output Organization

Logs are saved in subdirectories within the specified output directory:

- **time/** — Time-based logs  
- **level/** — Level-based logs  
- **module/** — Module-based logs  
- **height/** — Height-based logs  
- **pattern/** — Pattern-based logs

## Requirements

- Python 3.7+
- Dependencies listed in requirements.txt
- 
