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
import signal

@dataclass
class LogEntry:
    timestamp: str
    method: str
    status: str
    ip: str
    normalized_message: str
    original_message: str

class AdvancedLogAnalyzer:
    def __init__(self, chunk_size=1024*1024*10):  # 10MB chunks
        self.chunk_size = chunk_size
        self.pattern_lock = threading.Lock()
        self.results_queue = queue.Queue()
        self.dynamic_patterns = [
            r'height=\d+',
            r'peer=[a-f0-9]+',
            r'block_app_hash=[A-F0-9]+',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r':\d{4,5}',
            r'\b[a-fA-F0-9]{40,64}\b',
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z'
        ]
        
        self.logs_by_time = defaultdict(list)
        self.logs_by_method = defaultdict(list)
        self.logs_by_status = defaultdict(list)
        self.logs_by_ip = defaultdict(list)
        self.pattern_groups = defaultdict(list)

    def process_chunk(self, chunk: str, exclude_patterns: Set[str]) -> List[LogEntry]:
        entries = []
        for line in chunk.splitlines():
            if not line.strip():
                continue

            try:
                # Extract timestamp
                timestamp_str = ' '.join(line.split()[:2])

                # Parse JSON data
                request_start = line.find('Request: {')
                response_start = line.find('} Response:')
                
                if request_start != -1 and response_start != -1:
                    request_data = json.loads(line[request_start+9:response_start+1])
                    response_data = json.loads(line[response_start+11:])

                    # Extract key fields
                    method = request_data.get('method', 'unknown')
                    status = response_data.get('status', 'unknown')
                    
                    # Extract IP with fallback patterns
                    ip = 'unknown'
                    connecting_ip = request_data.get('connectingIP', '')
                    ip_match = re.search(r'cf-connecting-ip: ([\d\.]+)', connecting_ip)
                    if ip_match:
                        ip = ip_match.group(1)

                    # Create simplified pattern for grouping
                    pattern_parts = [
                        request_data.get('method', ''),
                        request_data.get('backend_name', ''),
                        request_data.get('url', '').split('?')[0],  # Base URL without params
                    ]
                    normalized = '|'.join(pattern_parts)
                    
                    # Check exclusion patterns
                    if any(re.search(pattern, normalized) for pattern in exclude_patterns):
                        continue

                    entries.append(LogEntry(
                        timestamp=timestamp_str,
                        method=method,
                        status=status,
                        ip=ip,
                        normalized_message=normalized,
                        original_message=line
                    ))

            except Exception as e:
                continue

        return entries

    def analyze_file(self, filename: str, exclude_patterns: Set[str] = None) -> None:
        if exclude_patterns is None:
            exclude_patterns = set()

        file_size = os.path.getsize(filename)
        chunks = []
        
        # Reset previous analysis
        self.logs_by_time.clear()
        self.logs_by_method.clear()
        self.logs_by_status.clear()
        self.logs_by_ip.clear()
        self.pattern_groups.clear()
        
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
                executor.submit(self.process_chunk, chunk, exclude_patterns)
                for chunk in chunks
            ]
            
            with tqdm(total=len(futures), desc="Processing chunks") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    entries = future.result()
                    self._organize_entries(entries)
                    pbar.update(1)

        print(f"\nProcessed {len(self.pattern_groups)} unique log patterns")

    def _organize_entries(self, entries: List[LogEntry]) -> None:
        for entry in entries:
            self.logs_by_time[entry.timestamp].append(entry)
            self.logs_by_method[entry.method].append(entry)
            self.logs_by_status[entry.status].append(entry)
            self.logs_by_ip[entry.ip].append(entry)
            self.pattern_groups[entry.normalized_message].append(entry)

    def save_organized_logs(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        
        with tqdm(total=4, desc="Saving organized logs") as pbar:
            # Save time-based logs
            for time, entries in self.logs_by_time.items():
                safe_time = re.sub(r'[^\w\-_\. ]', '_', time)
                with open(f"{output_dir}/time_{safe_time}.log", 'w') as f:
                    for entry in entries:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save method-based logs
            for method, entries in self.logs_by_method.items():
                with open(f"{output_dir}/method_{method}.log", 'w') as f:
                    for entry in entries:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save status-based logs
            for status, entries in self.logs_by_status.items():
                with open(f"{output_dir}/status_{status}.log", 'w') as f:
                    for entry in entries:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

            # Save IP-based logs (top IPs only)
            top_ips = sorted(self.logs_by_ip.items(), key=lambda x: len(x[1]), reverse=True)[:20]
            for ip, entries in top_ips:
                safe_ip = ip.replace('.', '_')
                with open(f"{output_dir}/ip_{safe_ip}.log", 'w') as f:
                    for entry in entries:
                        f.write(f"{entry.original_message}\n")
            pbar.update(1)

def show_exclusion_patterns_menu():
    print("\n=== Common patterns to exclude ===")
    patterns = [
        ("All successful responses (status 200)", r'"status":"200"'),
        ("All OPTIONS requests", r'"method":"OPTIONS"'),
        ("Specific IP", r'cf-connecting-ip: specific.ip.here'),
        ("Specific endpoint", r'"url":"/specific/endpoint"'),
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
            elif patterns[choice-1][1] == r'cf-connecting-ip: specific.ip.here':
                ip = input("Enter IP address to exclude: ")
                return f'cf-connecting-ip: {ip}'
            return patterns[choice-1][1]
    except (ValueError, IndexError):
        print("Invalid choice")
        return None

def interactive_analyzer():
    print("\nAdvanced Log Analyzer")
    print("===================")
    
    filename = input("Enter log file path: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
        
    output_dir = input("Enter output directory path: ").strip()
    
    analyzer = AdvancedLogAnalyzer()
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
                
                print("\nHTTP Methods:")
                for method, entries in analyzer.logs_by_method.items():
                    print(f"  {method}: {len(entries)}")
                    
                print("\nStatus Codes:")
                for status, entries in analyzer.logs_by_status.items():
                    print(f"  {status}: {len(entries)}")
                    
                print("\nTop IPs:")
                top_ips = sorted(analyzer.logs_by_ip.items(), key=lambda x: len(x[1]), reverse=True)[:10]
                for ip, entries in top_ips:
                    print(f"  {ip}: {len(entries)}")

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
                                    input("\nPress Enter to continue...")
                            except ValueError:
                                print("Invalid pattern number")
                    except Exception as e:
                        print(f"Error: {str(e)}")
                        
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
