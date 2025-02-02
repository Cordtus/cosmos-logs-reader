# Tendermint Log Analyzer

Analyzes and categorizes Tendermint/Cosmos SDK node logs in both JSON and plain text formats.

## Features

- Pattern-based log grouping
- Multi-threaded processing for large files
- Memory-efficient processing using mmap
- Handles both JSON and text log formats
- Module-based analysis
- Log level filtering
- Pattern search and filtering

## Installation

```bash
pip install -r requirements.txt
```

## Log Format Support

### JSON Format
```json
{"level":"info","module":"state","height":129505798,"time":"2025-02-02T22:01:53Z","message":"committed state"}
```

### Text Format
```
3:05PM DBG Received bytes chID=32 module=p2p msgBytes="..."
```

## Usage

```bash
python tendermint_logs.py
```

### Menu Options

1. **Analyze File**: Process and categorize log file
2. **View Summary**: Display statistics by module and log level
3. **Explore Patterns**: Browse and search log patterns
4. **Add Exclusion**: Filter out unwanted patterns
5. **Save Results**: Export organized logs to files

### Common Filters

- Debug level logs
- Height-related messages
- Peer-related messages
- Specific modules
- Custom regex patterns

## Output Organization

Logs are organized into:
- Time-based groups
- Module-based groups
- Log level groups
- Pattern-based groups

## Requirements

- Python 3.7+
- See requirements.txt for dependencies
