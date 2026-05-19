from __future__ import annotations

from datetime import datetime, timezone
from hashlib import md5, sha1, sha256
from pathlib import Path
import hashlib
import re
import subprocess
from typing import List, Dict
from datetime import datetime
import json

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False

# Constants
SUSPICIOUS_APIS = [
    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
    'ShellExecute', 'WinExec', 'CreateProcess', 'RegSetValue', 'RegCreateKey',
    'URLDownloadToFile', 'InternetOpen', 'socket', 'connect', 'WSAStartup',
    'CryptEncrypt', 'CryptDecrypt', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'SetWindowsHookEx', 'GetAsyncKeyState'
]

# Function 1: Compute Hashes
def compute_hashes(file_path: Path) -> dict:
    hashes = {}
    with file_path.open('rb') as f:
        data = f.read()
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    return hashes

# Function 2: Identify File Type
def identify_file_type(file_path: Path) -> str:
    with file_path.open('rb') as f:
        header = f.read(4)
        if header[:2] == b'MZ':
            return 'PE Executable'
        elif header[:4] == b'\x7fELF':
            return 'Linux Binary'
        elif header[:2] == b'PK':
            return 'ZIP Archive'
    return file_path.suffix.lower()

# Function 3: Analyze PE
def analyze_pe(file_path: Path) -> dict:
    if not PEFILE_AVAILABLE:
        return {'error': 'pefile_not_available'}
    try:
        pe = pefile.PE(str(file_path))
        analysis = {
            'sections': [],
            'imports': [],
            'compile_timestamp': None,
            'entry_point': None,
            'is_packed': False
        }

        # Sections
        for section in pe.sections:
            section_info = {
                'name': section.Name.decode().strip('\x00'),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'md5': hashlib.md5(section.get_data()).hexdigest(),
                'suspicious': section.get_entropy() > 7.2 or section.Name.decode().strip('\x00') in ['.packed', 'UPX0', 'UPX1', '.themida']
            }
            analysis['sections'].append(section_info)

        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    func_name = imp.name.decode() if imp.name else ''
                    analysis['imports'].append({
                        'dll': dll_name,
                        'function': func_name,
                        'suspicious': any(api in func_name for api in SUSPICIOUS_APIS)
                    })

        # Compile Timestamp
        timestamp = pe.FILE_HEADER.TimeDateStamp
        analysis['compile_timestamp'] = datetime.utcfromtimestamp(timestamp).isoformat() if timestamp > 0 else None

        # Entry Point
        analysis['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Packed Check
        analysis['is_packed'] = any(section['suspicious'] for section in analysis['sections']) or 'UPX' in pe.dump_info()

        return analysis
    except pefile.PEFormatError:
        return {'error': 'Invalid PE file'}

# Function 4: Extract Strings
def extract_strings(file_path: Path, min_length: int = 4) -> List[str]:
    with file_path.open('rb') as f:
        data = f.read()
    strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
    filtered_strings = set()
    for s in strings:
        decoded = s.decode(errors='ignore')
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', decoded) or \
           re.search(r'\b[a-zA-Z0-9.-]+\.(com|net|org|io|ru|cn|tk|xyz|top)\b', decoded) or \
           re.search(r'https?://', decoded) or \
           re.search(r'C:\\|%', decoded) or \
           re.search(r'HKEY_|SOFTWARE\\|SYSTEM\\', decoded) or \
           re.search(r'[A-Za-z0-9+/]{20,}={0,2}', decoded) or \
           any(keyword in decoded for keyword in ['cmd.exe', 'powershell', 'wget', 'curl', 'nc.exe', 'mimikatz', 'password', 'bitcoin', 'encrypt', 'ransom', 'tor', '.onion']):
            filtered_strings.add(decoded)
    return list(filtered_strings)[:200]

# Function 5: Run YARA
def run_yara(file_path: Path) -> List[Dict]:
    if not YARA_AVAILABLE:
        return []
    rules_dir = Path('backend/yara_rules')
    if not rules_dir.exists():
        return []
    try:
        rules = yara.compile(filepaths={str(rule): str(rule) for rule in rules_dir.glob('*.yar*')})
        matches = rules.match(str(file_path))
        results = []
        for match in matches:
            results.append({
                'rule_name': match.rule,
                'description': match.meta.get('description', ''),
                'tags': match.tags,
                'matched_strings': [s[2].decode(errors='ignore') for s in match.strings]
            })
        return results
    except yara.Error:
        return []

# Function 6: Run Full Analysis
async def run_full_analysis(file_path: Path, file_name: str) -> dict:
    hashes = compute_hashes(file_path)
    file_type = identify_file_type(file_path)
    pe_analysis = analyze_pe(file_path) if file_type == 'PE Executable' else {}
    strings = extract_strings(file_path)
    yara_matches = run_yara(file_path)

    result = {
        'file_name': file_name,
        'file_size': file_path.stat().st_size,
        'file_type': file_type,
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'sha256': hashes['sha256'],
        'pe_sections': pe_analysis.get('sections', []) if pe_analysis and 'error' not in pe_analysis else [],
        'imports': pe_analysis.get('imports', []) if pe_analysis and 'error' not in pe_analysis else [],
        'strings_extracted': strings,
        'yara_hits': yara_matches,
        'is_packed': pe_analysis.get('is_packed', False) if pe_analysis and 'error' not in pe_analysis else False,
        'compile_timestamp': pe_analysis.get('compile_timestamp') if pe_analysis and 'error' not in pe_analysis else None,
        'entry_point': pe_analysis.get('entry_point', '') if pe_analysis and 'error' not in pe_analysis else '',
    }

    output_dir = Path('/tmp/samples') / hashes['sha256']
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / 'static.json').open('w') as f:
        json.dump(result, f, indent=4)

    return result


async def execute(context: dict) -> dict:
    file_path_str = context.get("file_path")
    file_name = context.get("filename", "Unknown")
    if not file_path_str:
        return {"error": "Missing file_path in context for static analysis"}
    file_path = Path(file_path_str)
    result = await run_full_analysis(file_path, file_name)
    return {"static_analysis": result, "sha256": result.get("sha256")}
