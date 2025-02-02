#!/usr/bin/env python3
import re
import json
import mmap
import os
import sys
import threading
import concurrent.futures
import argparse
import logging
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any, Generator
from enum import Enum

from tqdm import tqdm
from rich.console import Console
from rich.prompt import Prompt

# Setup a rich console for pretty printing.
console = Console()


# --- Data Structures and LogEntry class ---

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


# --- The Analyzer Class ---

class TendermintLogAnalyzer:
    def __init__(self, chunk_size: int = 10 * 1024 * 1024):
        self.chunk_size = chunk_size
        self.pattern_lock = threading.Lock()
        self.max_samples = 5

        # Aggregated counts and a few sample entries (to save memory)
        self.pattern_counts: Dict[str, int] = defaultdict(int)
        self.pattern_samples: Dict[str, List[LogEntry]] = defaultdict(list)
        self.time_counts: Dict[str, int] = defaultdict(int)
        self.time_samples: Dict[str, List[LogEntry]] = defaultdict(list)
        self.level_counts: Dict[str, int] = defaultdict(int)
        self.level_samples: Dict[str, List[LogEntry]] = defaultdict(list)
        self.module_counts: Dict[str, int] = defaultdict(int)
        self.module_samples: Dict[str, List[LogEntry]] = defaultdict(list)
        self.height_counts: Dict[int, int] = defaultdict(int)
        self.height_samples: Dict[int, List[LogEntry]] = defaultdict(list)

        # Patterns to “normalize” away (Tendermint/Cosmos specific)
        self.patterns = [
            r'height=\d+',
            r'H:\d+',
            r'peer=[a-f0-9]+',
            r'block_app_hash=[A-F0-9]+',
            r'block_hash=[A-F0-9]+',
            r'\b[a-fA-F0-9]{40,64}\b',  # addresses/hashes
            r'chId=\d+',
            r'num_txs=\d+',
            r'round=\d+',
            r'\[\d+\]',               # vote indices
            r'@[^:]+:\d+',            # peer addresses
            r'latency_ms=\d+'
        ]
        # Precompile normalization regexes for speed.
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

        # Precompile the text log regex (adjust if necessary)
        self.text_log_re = re.compile(r'^([\d:APM]+)\s+(\w+)\s+(.+)$')

    def detect_format(self, first_line: str) -> LogFormat:
        # (Mostly for backward compatibility.)
        try:
            json.loads(first_line)
            return LogFormat.JSON
        except json.JSONDecodeError:
            return LogFormat.TEXT

    def parse_json_log(self, line: str) -> Optional[LogEntry]:
        try:
            data = json.loads(line)
            height = None
            if 'height' in data:
                try:
                    height = int(data['height'])
                except (ValueError, TypeError):
                    pass
            msg = data.get('message', '')
            return LogEntry(
                timestamp=data.get('time', ''),
                level=data.get('level', '').upper(),
                module=data.get('module', ''),
                message=msg,
                height=height,
                original_message=line,
                normalized_message=self.normalize_message(msg),
                metadata=data
            )
        except json.JSONDecodeError:
            return None

    def parse_text_log(self, line: str) -> Optional[LogEntry]:
        try:
            match = self.text_log_re.match(line)
            if match:
                timestamp, level, message = match.groups()
                module = None
                module_match = re.search(r'module=(\w+)', message)
                if module_match:
                    module = module_match.group(1)
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
        except Exception as e:
            logging.debug(f"parse_text_log error: {e}")
            return None
        return None

    def normalize_message(self, message: str) -> str:
        normalized = message
        with self.pattern_lock:
            for cp in self.compiled_patterns:
                normalized = cp.sub('<DYNAMIC>', normalized)
        return normalized

    def process_chunk(self, chunk: str, exclude_patterns: Set[str]) -> List[LogEntry]:
        entries = []
        for line in chunk.splitlines():
            if not line.strip():
                continue
            # Try JSON first; if that fails, try text parsing.
            entry = self.parse_json_log(line)
            if entry is None:
                entry = self.parse_text_log(line)
            if entry and not any(re.search(pattern, entry.normalized_message) for pattern in exclude_patterns):
                entries.append(entry)
        return entries

    def _chunk_generator(self, mm_obj: mmap.mmap, progress_bar: Optional[tqdm] = None) -> Generator[str, None, None]:
        """Yield complete chunks (ending on a newline) from the mmap object.
        Updates the provided progress_bar with the number of bytes read."""
        leftover = ""
        while True:
            data = mm_obj.read(self.chunk_size)
            if progress_bar is not None:
                progress_bar.update(len(data))
            if not data:
                if leftover:
                    yield leftover
                break
            chunk = leftover + data.decode('utf-8', errors='ignore')
            last_newline = chunk.rfind('\n')
            if last_newline == -1:
                leftover = chunk
                continue
            complete_chunk = chunk[:last_newline]
            leftover = chunk[last_newline + 1:]
            yield complete_chunk

    def analyze_file(self, filename: str, exclude_patterns: Optional[Set[str]] = None) -> None:
        if exclude_patterns is None:
            exclude_patterns = set()

        # Clear previous results.
        self.pattern_counts.clear()
        self.pattern_samples.clear()
        self.time_counts.clear()
        self.time_samples.clear()
        self.level_counts.clear()
        self.level_samples.clear()
        self.module_counts.clear()
        self.module_samples.clear()
        self.height_counts.clear()
        self.height_samples.clear()

        file_size = os.path.getsize(filename)

        # (Optionally, you could read the first line to check format, but here we try both parsers.)
        with open(filename, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            _ = self.detect_format(first_line)

        with open(filename, 'rb') as f:
            mm_obj = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            # Create a progress bar for file reading.
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Reading file") as read_bar:
                chunk_gen = self._chunk_generator(mm_obj, read_bar)
                # Compute an approximate total number of chunks for progress display.
                total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
                # Process chunks concurrently.
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    futures = executor.map(
                        lambda chunk: self.process_chunk(chunk, exclude_patterns),
                        chunk_gen
                    )
                    for entries in tqdm(futures, total=total_chunks, unit="chunk", desc="Processing chunks"):
                        self._organize_entries(entries)

        total_entries = sum(self.pattern_counts.values())
        if total_entries == 0:
            console.print("[bold red]Warning:[/bold red] No log entries parsed. Check the file format!")
        else:
            console.print(f"\n[bold green]Processed {total_entries} log entries.[/bold green]")

    def _organize_entries(self, entries: List[LogEntry]) -> None:
        for entry in entries:
            pattern = entry.normalized_message
            self.pattern_counts[pattern] += 1
            if len(self.pattern_samples[pattern]) < self.max_samples:
                self.pattern_samples[pattern].append(entry)

            self.time_counts[entry.timestamp] += 1
            if len(self.time_samples[entry.timestamp]) < self.max_samples:
                self.time_samples[entry.timestamp].append(entry)

            self.level_counts[entry.level] += 1
            if len(self.level_samples[entry.level]) < self.max_samples:
                self.level_samples[entry.level].append(entry)

            if entry.module:
                self.module_counts[entry.module] += 1
                if len(self.module_samples[entry.module]) < self.max_samples:
                    self.module_samples[entry.module].append(entry)

            if entry.height is not None:
                self.height_counts[entry.height] += 1
                if len(self.height_samples[entry.height]) < self.max_samples:
                    self.height_samples[entry.height].append(entry)

    def save_organized_logs(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        with tqdm(total=5, desc="Saving organized logs") as pbar:
            # Save time-based logs.
            for time_key, count in self.time_counts.items():
                safe_time = re.sub(r'[^\w\-_\. ]', '_', time_key)
                with open(os.path.join(output_dir, f"time_{safe_time}.log"), 'w', encoding='utf-8') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.time_samples[time_key]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save level-based logs.
            for level, count in self.level_counts.items():
                with open(os.path.join(output_dir, f"level_{level}.log"), 'w', encoding='utf-8') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.level_samples[level]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save module-based logs.
            for module, count in self.module_counts.items():
                safe_module = re.sub(r'[^\w\-_\.]', '_', module)
                with open(os.path.join(output_dir, f"module_{safe_module}.log"), 'w', encoding='utf-8') as f:
                    f.write(f"Total entries: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.module_samples[module]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save height-based logs (group by range, e.g. 0xxx, 1xxx, etc.)
            height_ranges = defaultdict(lambda: [0, []])  # range_key -> [count, samples]
            for height, count in self.height_counts.items():
                range_key = f"{height // 1000}xxx"
                height_ranges[range_key][0] += count
                if len(height_ranges[range_key][1]) < self.max_samples:
                    height_ranges[range_key][1].extend(
                        self.height_samples[height][: self.max_samples - len(height_ranges[range_key][1])]
                    )
            for range_key, (count, samples) in height_ranges.items():
                with open(os.path.join(output_dir, f"height_{range_key}.log"), 'w', encoding='utf-8') as f:
                    f.write(f"Total entries in range: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in samples:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save pattern-based logs (top 50 patterns).
            top_patterns = sorted(self.pattern_counts.items(), key=lambda x: x[1], reverse=True)[:50]
            for i, (pattern, count) in enumerate(top_patterns):
                with open(os.path.join(output_dir, f"pattern_{i:03d}.log"), 'w', encoding='utf-8') as f:
                    f.write(f"Pattern: {pattern}\n")
                    f.write(f"Occurrences: {count}\n")
                    f.write("-" * 80 + "\n")
                    for entry in self.pattern_samples[pattern]:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)


# --- Interactive Menu and CLI Mode ---

def interactive_analyzer() -> None:
    console.print("[bold blue]Tendermint Log Analyzer[/bold blue]")
    console.print("=======================")
    input_file = Prompt.ask("Enter log file path").strip()
    if not os.path.exists(input_file):
        console.print(f"[bold red]Error:[/bold red] File '{input_file}' not found")
        return
    output_dir = Prompt.ask("Enter output directory path").strip()
    analyzer = TendermintLogAnalyzer()
    exclude_patterns: Set[str] = set()

    while True:
        console.print("\n[bold blue]=== Log Analysis Menu ===[/bold blue]")
        console.print("1. Analyze file")
        console.print("2. View summary")
        console.print("3. Explore pattern groups")
        console.print("4. Add exclusion pattern")
        console.print("5. Save organized logs")
        console.print("6. Exit")
        choice = Prompt.ask("Enter your choice (1-6)").strip()

        try:
            if choice == '1':
                analyzer.analyze_file(input_file, exclude_patterns)

            elif choice == '2':
                total_logs = sum(analyzer.pattern_counts.values())
                if total_logs == 0:
                    console.print("No analysis results. Please run analysis first.")
                    continue
                console.print("\n[bold green]=== Analysis Summary ===[/bold green]")
                console.print(f"Total logs: {total_logs}")
                console.print(f"Unique patterns: {len(analyzer.pattern_counts)}")
                console.print("\n[bold]Log Levels:[/bold]")
                for level, count in analyzer.level_counts.items():
                    console.print(f"  {level}: {count}")
                console.print("\n[bold]Top Modules:[/bold]")
                sorted_modules = sorted(analyzer.module_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                for module, count in sorted_modules:
                    console.print(f"  {module}: {count}")
                console.print("\n[bold]Height Ranges:[/bold]")
                height_ranges = defaultdict(int)
                for height, count in analyzer.height_counts.items():
                    range_key = f"{height // 1000}xxx"
                    height_ranges[range_key] += count
                for range_key, count in sorted(height_ranges.items()):
                    console.print(f"  {range_key}: {count}")

            elif choice == '3':
                if not analyzer.pattern_counts:
                    console.print("No analysis results. Please run analysis first.")
                    continue
                sorted_patterns = sorted(analyzer.pattern_counts.items(), key=lambda x: x[1], reverse=True)
                page_size = 10
                current_page = 0
                total_pages = (len(sorted_patterns) + page_size - 1) // page_size

                while True:
                    console.print(f"\n[bold blue]=== Pattern Groups (Page {current_page + 1}/{total_pages}) ===[/bold blue]")
                    console.print("1. View most frequent patterns")
                    console.print("2. View least frequent patterns")
                    console.print("3. Search patterns")
                    console.print("4. Filter by occurrence count")
                    console.print("5. Next page")
                    console.print("6. Previous page")
                    console.print("7. Back to main menu")
                    subchoice = Prompt.ask("Choose option (1-7)").strip()

                    # Default ordering is descending by frequency.
                    patterns = sorted_patterns
                    if subchoice == '1':
                        patterns = sorted_patterns
                    elif subchoice == '2':
                        patterns = list(reversed(sorted_patterns))
                    elif subchoice == '3':
                        search = Prompt.ask("Enter search term").lower()
                        patterns = [p for p in sorted_patterns if search in p[0].lower()]
                    elif subchoice == '4':
                        try:
                            min_count = int(Prompt.ask("Enter minimum occurrence count"))
                            patterns = [p for p in sorted_patterns if p[1] >= min_count]
                        except ValueError:
                            console.print("Invalid number")
                            continue
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
                        console.print("Invalid choice")
                        continue

                    start_idx = current_page * page_size
                    end_idx = start_idx + page_size
                    page_patterns = patterns[start_idx:end_idx]
                    console.print("\n[bold]Current patterns:[/bold]")
                    for i, (pattern, count) in enumerate(page_patterns, start=start_idx):
                        sample = analyzer.pattern_samples[pattern][0].original_message if analyzer.pattern_samples[pattern] else ""
                        console.print(f"\n[{i}] {count} occurrences:")
                        console.print(f"Pattern: {pattern}")
                        console.print(f"Sample: {sample[:100]}...")
                    pat_choice = Prompt.ask("Enter pattern number to explore (or 'b' for back)").strip()
                    if pat_choice.lower() == 'b':
                        continue
                    try:
                        idx = int(pat_choice)
                        if 0 <= idx < len(patterns):
                            pattern, count = patterns[idx]
                            console.print(f"\n[bold green]=== Sample logs for pattern {idx} ===[/bold green]")
                            for entry in analyzer.pattern_samples[pattern]:
                                console.print(f"\n{entry.original_message}")
                                if entry.module:
                                    console.print(f"Module: {entry.module}")
                                if entry.height is not None:
                                    console.print(f"Height: {entry.height}")
                            Prompt.ask("\nPress Enter to continue")
                    except ValueError:
                        console.print("Invalid pattern number")

            elif choice == '4':
                pat = Prompt.ask("\nEnter exclusion regex pattern (or 'b' for back)").strip()
                if pat.lower() != 'b' and pat:
                    exclude_patterns.add(pat)
                    console.print(f"Added exclusion pattern. Total patterns: {len(exclude_patterns)}")

            elif choice == '5':
                if not analyzer.pattern_counts:
                    console.print("No analysis results. Please run analysis first.")
                    continue
                analyzer.save_organized_logs(output_dir)
                console.print(f"Logs organized and saved to [bold green]{output_dir}[/bold green]")

            elif choice == '6':
                break

        except KeyboardInterrupt:
            console.print("\nOperation cancelled. Returning to menu...")
            continue


def main():
    parser = argparse.ArgumentParser(description="Tendermint Log Analyzer")
    parser.add_argument("--input", "-i", type=str, help="Path to input log file")
    parser.add_argument("--output", "-o", type=str, help="Path to output directory")
    parser.add_argument("--exclude", "-e", action="append", help="Exclusion regex pattern (can be used multiple times)", default=[])
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.input and args.output:
        # Non-interactive (command-line) mode.
        analyzer = TendermintLogAnalyzer()
        exclude_patterns = set(args.exclude)
        console.print(f"[bold green]Analyzing file:[/bold green] {args.input}")
        analyzer.analyze_file(args.input, exclude_patterns)
        console.print(f"[bold green]Saving organized logs to:[/bold green] {args.output}")
        analyzer.save_organized_logs(args.output)
        console.print("[bold green]Analysis complete.[/bold green]")
    else:
        interactive_analyzer()


if __name__ == "__main__":
    main()
