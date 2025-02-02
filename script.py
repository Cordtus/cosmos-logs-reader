import re
import json
import mmap
import os
from datetime import datetime
from collections import defaultdict
import concurrent.futures
import threading
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass
import queue
from tqdm import tqdm
import readline
import sys
from enum import Enum

class LogFormat(Enum):
    JSON = "json"
    TEXT = "text"

@dataclass
class LogEntry:
    timestamp: str
    level: str
    module: Optional[str]
    message: str
    height: Optional[int]
    original_message: str
    normalized_message: str
    metadata: Dict[str, Any]

class TendermintLogAnalyzer:
    def __init__(self, chunk_size=1024*1024*10):
        self.chunk_size = chunk_size
        self.pattern_lock = threading.Lock()
        
        # Store counts instead of full entries
        self.pattern_counts = defaultdict(int)
        self.level_counts = defaultdict(int)
        self.module_counts = defaultdict(int)
        self.height_counts = defaultdict(int)
        
        # Keep only sample entries for patterns
        self.pattern_samples = {}  # Store just a few examples per pattern
        self.max_samples = 5
        
        # Tendermint/Cosmos specific patterns
        self.patterns = [
            r'height=\d+',
            r'H:\d+',
            r'peer=[a-f0-9]+',
            r'block_app_hash=[A-F0-9]+',
            r'block_hash=[A-F0-9]+',
            r'\b[a-fA-F0-9]{40,64}\b',  # For addresses, hashes
            r'chId=\d+',
            r'num_txs=\d+',
            r'round=\d+',
            r'\[\d+\]',  # For vote indices
            r'@[^:]+:\d+',  # For peer addresses
            r'latency_ms=\d+'
        ]
        
        self.logs_by_time = defaultdict(list)
        self.logs_by_level = defaultdict(list)
        self.logs_by_module = defaultdict(list)
        self.logs_by_height = defaultdict(list)
        self.pattern_groups = defaultdict(list)

    def detect_format(self, first_line: str) -> LogFormat:
        try:
            json.loads(first_line)
            return LogFormat.JSON
        except:
            return LogFormat.TEXT

    def parse_json_log(self, line: str) -> Optional[LogEntry]:
        try:
            data = json.loads(line)
            # Convert height to int explicitly
            height = None
            if 'height' in data:
                try:
                    height = int(data['height'])
                except (ValueError, TypeError):
                    pass
                
            return LogEntry(
                timestamp=data.get('time', ''),
                level=data.get('level', '').upper(),
                module=data.get('module', ''),
                message=data.get('message', ''),
                height=height,  # Now properly typed as Optional[int]
                original_message=line,
                normalized_message=self.normalize_message(data.get('message', '')),
                metadata=data
            )
        except:
            return None

    def parse_text_log(self, line: str) -> Optional[LogEntry]:
        try:
            # Match pattern like: "3:05PM DBG Received bytes chID=32..."
            match = re.match(r'^([\d:APM]+)\s+(\w+)\s+(.+)$', line)
            if match:
                timestamp, level, message = match.groups()
                
                # Extract module if present
                module = None
                module_match = re.search(r'module=(\w+)', message)
                if module_match:
                    module = module_match.group(1)
                
                # Extract height if present
                height = None
                height_match = re.search(r'height=(\d+)', message)
                if height_match:
                    height = int(height_match.group(1))
                
                return LogEntry(
                    timestamp=timestamp,
                    level=level,
                    module=module,
                    message=message,
                    height=height,
                    original_message=line,
                    normalized_message=self.normalize_message(message),
                    metadata={'raw_level': level}
                )
        except:
            return None
        return None

    def normalize_message(self, message: str) -> str:
        normalized = message
        with self.pattern_lock:
            for pattern in self.patterns:
                normalized = re.sub(pattern, '<DYNAMIC>', normalized)
        return normalized

    def process_chunk(self, chunk: str, log_format: LogFormat, exclude_patterns: Set[str]) -> List[LogEntry]:
        entries = []
        for line in chunk.splitlines():
            if not line.strip():
                continue

            entry = None
            if log_format == LogFormat.JSON:
                entry = self.parse_json_log(line)
            else:
                entry = self.parse_text_log(line)

            if entry and not any(re.search(pattern, entry.normalized_message) for pattern in exclude_patterns):
                entries.append(entry)

        return entries

    def analyze_file(self, filename: str, exclude_patterns: Set[str] = None) -> None:
        if exclude_patterns is None:
            exclude_patterns = set()

        # Reset previous analysis
        self.logs_by_time.clear()
        self.logs_by_level.clear()
        self.logs_by_module.clear()
        self.logs_by_height.clear()
        self.pattern_groups.clear()

        file_size = os.path.getsize(filename)
        
        # Detect format from first line
        with open(filename, 'r') as f:
            first_line = f.readline().strip()
            log_format = self.detect_format(first_line)

        chunks = []
        with open(filename, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Reading file") as pbar:
                while True:
                    chunk = mm.read(self.chunk_size).decode('utf-8', errors='ignore')
                    if not chunk:
                        break
                    chunks.append(chunk)
                    pbar.update(len(chunk.encode('utf-8')))

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(self.process_chunk, chunk, log_format, exclude_patterns)
                for chunk in chunks
            ]
            
            with tqdm(total=len(futures), desc="Processing chunks") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    entries = future.result()
                    self._organize_entries(entries)
                    pbar.update(1)

        print(f"\nProcessed {sum(len(entries) for entries in self.pattern_groups.values())} log entries")

    def _organize_entries(self, entries: List[LogEntry]) -> None:
        for entry in entries:
            pattern = entry.normalized_message
            
            # Update counts
            self.pattern_counts[pattern] += 1
            if entry.level:
                self.level_counts[entry.level] += 1
            if entry.module:
                self.module_counts[entry.module] += 1
            if entry.height is not None:
                self.height_counts[entry.height] += 1
            
            # Store sample if needed
            if pattern not in self.pattern_samples:
                self.pattern_samples[pattern] = []
            if len(self.pattern_samples[pattern]) < self.max_samples:
                self.pattern_samples[pattern].append(entry)


    def save_organized_logs(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)

        with tqdm(total=5, desc="Saving organized logs") as pbar:
            # Save time-based logs in chunks
            for time_key, count in self.time_counts.items():
                safe_time = re.sub(r'[^\w\-_\. ]', '_', time_key)
                with open(f"{output_dir}/time_{safe_time}.log", 'w') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.time_samples[time_key]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save level-based logs
            for level, count in self.level_counts.items():
                with open(f"{output_dir}/level_{level}.log", 'w') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.level_samples[level]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save module-based logs
            for module, count in self.module_counts.items():
                safe_module = re.sub(r'[^\w\-_\.]', '_', module)
                with open(f"{output_dir}/module_{safe_module}.log", 'w') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.module_samples[module]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save height-based logs
            height_ranges = defaultdict(int)
            height_range_samples = defaultdict(list)

            for height, count in self.height_counts.items():
                range_key = f"{height//1000}xxx"
                height_ranges[range_key] += count

                # Keep sample entries for each range
                if len(height_range_samples[range_key]) < self.max_samples:
                    height_range_samples[range_key].extend(
                        self.height_samples.get(height, [])[:self.max_samples - len(height_range_samples[range_key])]
                    )

            for range_key, count in height_ranges.items():
                with open(f"{output_dir}/height_{range_key}.log", 'w') as f:
                    f.write(f"Total entries in range: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in sorted(height_range_samples[range_key], key=lambda x: x.height):
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save pattern-based logs (top patterns only)
            top_patterns = sorted(
                self.pattern_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:50]

            for i, (pattern, count) in enumerate(top_patterns):
                with open(f"{output_dir}/pattern_{i:03d}.log", 'w') as f:
                    f.write(f"Pattern: {pattern}\n")
                    f.write(f"Occurrences: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.pattern_samples[pattern]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

def show_exclusion_patterns_menu():
    print("\n=== Common patterns to exclude ===")
    patterns = [
        ("Debug level logs", r'DBG|debug'),
("Info level logs", r'INFO|info'),
        ("Consensus-related logs", r'module="consensus"'),
        ("Height-related logs", r'height=\d+'),
        ("Peer-related logs", r'peer=[a-f0-9]+'),
        ("Block hash logs", r'block_hash=[A-F0-9]+'),
        ("Custom regex pattern", "custom")
    ]
    
    for i, (desc, pattern) in enumerate(patterns, 1):
        print(f"{i}. {desc}")
    
    try:
        choice = input("\nEnter number (or 'b' for back): ")
        if choice.lower() == 'b':
            return None
            
        choice = int(choice)
        if 1 <= choice <= len(patterns):
            if patterns[choice-1][1] == "custom":
                return input("Enter your custom regex pattern: ")
            return patterns[choice-1][1]
    except (ValueError, IndexError):
        print("Invalid choice")
        return None

def interactive_analyzer():
    print("\nTendermint Log Analyzer")
    print("===================")
    
    filename = input("Enter log file path: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
        
    output_dir = input("Enter output directory path: ").strip()
    
    analyzer = TendermintLogAnalyzer()
    exclude_patterns = set()

    while True:
        try:
            print("\n=== Log Analysis Menu ===")
            print("1. Analyze file")
            print("2. View summary")
            print("3. Explore pattern groups")
            print("4. Add exclusion pattern")
            print("5. Save organized logs")
            print("6. Exit")

            choice = input("\nEnter your choice (1-6): ").strip()

            if choice == '1':
                analyzer.analyze_file(filename, exclude_patterns)

            elif choice == '2':
                if not analyzer.pattern_groups:
                    print("No analysis results. Please run analysis first.")
                    continue
                    
                print("\n=== Analysis Summary ===")
                print(f"Total logs: {sum(len(entries) for entries in analyzer.pattern_groups.values())}")
                print(f"Unique patterns: {len(analyzer.pattern_groups)}")
                
                print("\nLog Levels:")
                for level, entries in analyzer.logs_by_level.items():
                    print(f"  {level}: {len(entries)}")
                
                print("\nTop Modules:")
                sorted_modules = sorted(
                    analyzer.logs_by_module.items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )[:10]
                for module, entries in sorted_modules:
                    print(f"  {module}: {len(entries)}")

                print("\nHeight Ranges:")
                height_ranges = defaultdict(int)
                for height, entries in analyzer.logs_by_height.items():
                    range_key = f"{height//1000}xxx"
                    height_ranges[range_key] += len(entries)
                for range_key, count in sorted(height_ranges.items()):
                    print(f"  {range_key}: {count}")

            elif choice == '3':
                if not analyzer.pattern_groups:
                    print("No analysis results. Please run analysis first.")
                    continue

                sorted_patterns = sorted(
                    analyzer.pattern_groups.items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )

                page_size = 10
                current_page = 0
                total_pages = (len(sorted_patterns) + page_size - 1) // page_size

                while True:
                    print(f"\n=== Pattern Groups (Page {current_page + 1}/{total_pages}) ===")
                    print("1. View most frequent patterns")
                    print("2. View least frequent patterns")
                    print("3. Search patterns")
                    print("4. Filter by occurrence count")
                    print("5. Next page")
                    print("6. Previous page")
                    print("7. Back to main menu")

                    subchoice = input("\nChoose option (1-7): ").strip()

                    try:
                        if subchoice == '1':
                            patterns = sorted_patterns
                        elif subchoice == '2':
                            patterns = list(reversed(sorted_patterns))
                        elif subchoice == '3':
                            search = input("Enter search term: ").lower()
                            patterns = [p for p in sorted_patterns if search in p[0].lower()]
                        elif subchoice == '4':
                            min_count = int(input("Enter minimum occurrence count: "))
                            patterns = [p for p in sorted_patterns if len(p[1]) >= min_count]
                        elif subchoice == '5':
                            if current_page < total_pages - 1:
                                current_page += 1
                            continue
                        elif subchoice == '6':
                            if current_page > 0:
                                current_page -= 1
                            continue
                        elif subchoice == '7':
                            break
                        else:
                            print("Invalid choice")
                            continue

                        start_idx = current_page * page_size
                        end_idx = start_idx + page_size
                        page_patterns = patterns[start_idx:end_idx]

                        print("\nCurrent patterns:")
                        for i, (pattern, entries) in enumerate(page_patterns, start=start_idx):
                            print(f"\n[{i}] {len(entries)} occurrences:")
                            print(f"Pattern: {pattern}")
                            print(f"Sample: {entries[0].original_message[:100]}...")

                        pattern_choice = input("\nEnter pattern number to explore (or 'b' for back): ")
                        if pattern_choice.lower() != 'b':
                            try:
                                idx = int(pattern_choice)
                                if 0 <= idx < len(patterns):
                                    pattern, entries = patterns[idx]
                                    print(f"\n=== Sample logs for pattern {idx} ===")
                                    for entry in entries[:5]:
                                        print(f"\n{entry.original_message}")
                                        if entry.module:
                                            print(f"Module: {entry.module}")
                                        if entry.height:
                                            print(f"Height: {entry.height}")
                                    input("\nPress Enter to continue...")
                            except ValueError:
                                print("Invalid pattern number")
                    except Exception as e:
                        print(f"Error: {str(e)}")
                        continue

            elif choice == '4':
                pattern = show_exclusion_patterns_menu()
                if pattern:
                    exclude_patterns.add(pattern)
                    print(f"Added exclusion pattern. Current patterns: {len(exclude_patterns)}")

            elif choice == '5':
                if not analyzer.pattern_groups:
                    print("No analysis results. Please run analysis first.")
                    continue
                analyzer.save_organized_logs(output_dir)
                print(f"Logs organized and saved to {output_dir}")

            elif choice == '6':
                break

        except KeyboardInterrupt:
            print("\nOperation cancelled. Returning to menu...")
            continue

if __name__ == "__main__":
    interactive_analyzer()
