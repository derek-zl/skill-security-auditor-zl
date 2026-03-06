#!/usr/bin/env python3
"""
skill-security-auditor v2: Multi-language static analysis scanner for Claude Skill packages.

Supported languages/file types:
  Shell/Bash, Python, JavaScript/TypeScript, Ruby, PHP, Go, Rust,
  PowerShell, Java/Kotlin, Swift, Lua, R, SQL,
  Config: Dockerfile, .env, docker-compose, requirements.txt, package.json
  Markup: Markdown/SKILL.md, YAML, HTML
  Cross-cutting: Obfuscation, exfiltration, zip-slip, DNS exfil, Base64 decode

Usage:
    python audit_skill.py <path-to-skill-folder-or-.skill-file>
"""

import os, re, sys, json, zipfile, tempfile, base64
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Set

# ─────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────

@dataclass
class Finding:
    id: str
    severity: str
    title: str
    file: str
    line: Optional[int]
    snippet: str
    explanation: str
    fix: str
    language: str = "general"

@dataclass
class AuditReport:
    skill_name: str
    files_scanned: List[str]
    skipped_binary: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def verdict(self):
        s = {f.severity for f in self.findings}
        return "DANGEROUS" if "HIGH" in s else "CAUTION" if "MEDIUM" in s else "SAFE"

    @property
    def counts(self):
        return {k: sum(1 for f in self.findings if f.severity==k) for k in ("HIGH","MEDIUM","LOW")}

# ─────────────────────────────────────────
# Extension / filename → language
# ─────────────────────────────────────────

EXT_TO_LANG = {
    '.sh':'shell','.bash':'shell','.zsh':'shell','.fish':'shell',
    '.py':'python','.pyw':'python',
    '.js':'javascript','.mjs':'javascript','.cjs':'javascript','.jsx':'javascript',
    '.ts':'typescript','.tsx':'typescript',
    '.rb':'ruby','.rake':'ruby','.gemspec':'ruby',
    '.php':'php','.phtml':'php',
    '.go':'go',
    '.rs':'rust',
    '.ps1':'powershell','.psm1':'powershell','.psd1':'powershell',
    '.java':'java','.kt':'kotlin','.kts':'kotlin',
    '.swift':'swift',
    '.lua':'lua',
    '.r':'r',
    '.sql':'sql',
    '.md':'markdown','.txt':'text',
    '.yaml':'yaml','.yml':'yaml',
    '.json':'json',
    '.html':'html','.htm':'html',
    '.toml':'toml','.ini':'ini','.cfg':'ini',
    '.env':'dotenv','.envrc':'dotenv',
    '.dockerfile':'dockerfile',
}

SPECIAL_FILENAMES = {
    'dockerfile':'dockerfile','docker-compose.yml':'yaml','docker-compose.yaml':'yaml',
    'requirements.txt':'requirements','package.json':'packagejson',
    'gemfile':'ruby','rakefile':'ruby','makefile':'makefile',
    '.env':'dotenv','.envrc':'dotenv',
}

def detect_language(fpath: Path) -> str:
    n = fpath.name.lower()
    if n in SPECIAL_FILENAMES: return SPECIAL_FILENAMES[n]
    return EXT_TO_LANG.get(fpath.suffix.lower(), 'text')

# ─────────────────────────────────────────
# Pattern catalog
# applies_to=None  → all files
# applies_to={...} → only matching langs
# ─────────────────────────────────────────

PATTERNS = [
  # ── SHELL ──────────────────────────────────────────
  dict(id="SH-001",severity="HIGH",language="shell",title="Remote code execution via pipe-to-shell",
    pattern=r"(curl|wget)\s+[^\|#\n]*\|\s*(ba)?sh",applies_to={'shell','markdown','text','dockerfile'},
    explanation="Downloads and immediately executes arbitrary remote code — classic supply-chain attack.",
    fix="Download to a named file first, verify a checksum, then execute."),
  dict(id="SH-002",severity="HIGH",language="shell",title="SSH private key read",
    pattern=r"(cat|cp|read|tee|base64)\s+['\"]?~?\/?(home\/\w+\/)?\.ssh\/(id_rsa|id_ed25519|id_ecdsa|id_dsa)",
    applies_to={'shell','markdown','text'},
    explanation="Reads SSH private keys enabling remote server access.",
    fix="Remove credential file access entirely."),
  dict(id="SH-003",severity="HIGH",language="shell",title="Cloud credentials file access",
    pattern=r"(cat|cp|read|tee)\s+['\"]?~?\/?\.aws\/credentials|~?\/?\.config\/gcloud|~?\/?\.azure",
    applies_to={'shell','markdown','text'},
    explanation="Reads AWS/GCP/Azure credentials enabling cloud account takeover.",
    fix="Remove credential file access."),
  dict(id="SH-004",severity="HIGH",language="shell",title="Shell profile persistence",
    pattern=r"(>>|tee\s+-a)\s+['\"]?~?\/?(home\/\w+\/)?\.?(bashrc|zshrc|bash_profile|profile|fish_config|zprofile)",
    applies_to={'shell','markdown','text'},
    explanation="Writes to shell startup files — creates code that runs every terminal session.",
    fix="Remove shell profile modifications."),
  dict(id="SH-005",severity="HIGH",language="shell",title="Cron job injection",
    pattern=r"crontab\s+(-l[^;]*\|[^;]*crontab|-e|\s+[^-])|\/etc\/cron\.",
    applies_to={'shell','markdown','text'},
    explanation="Installs a persistent background job executing arbitrary code.",
    fix="Remove cron manipulation."),
  dict(id="SH-006",severity="HIGH",language="shell",title="Sudo privilege escalation",
    pattern=r"\bsudo\s+(?!-n\s+true)",applies_to={'shell','markdown','text','dockerfile'},
    explanation="Requests root — can modify system files or install backdoors.",
    fix="Remove sudo. Skills must operate without elevated privileges."),
  dict(id="SH-007",severity="HIGH",language="shell",title="Write to system directories",
    pattern=r"(>\s*|tee\s+|cp\s+\S+\s+|mv\s+\S+\s+|install\s+)['\"]?\/(etc|usr|bin|sbin|lib|boot|sys|proc)\/",
    applies_to={'shell','markdown'},
    explanation="Writes to OS system directories — potential OS backdoor.",
    fix="Write only to /tmp/ or the skill's working directory."),
  dict(id="SH-008",severity="HIGH",language="shell",title="systemd / launchd persistence",
    pattern=r"systemctl\s+(enable|start|daemon-reload)|launchctl\s+(load|submit)|\/etc\/systemd\/system\/.+\.service",
    applies_to={'shell','markdown','text'},
    explanation="Registers a system service that auto-starts on boot.",
    fix="Remove service registration."),
  dict(id="SH-009",severity="MEDIUM",language="shell",title="Recursive filesystem enumeration",
    pattern=r"find\s+\/\s+|find\s+~\s+|ls\s+-[lRra]*R\b|du\s+-[ash]*\s+\/",
    applies_to={'shell','markdown'},
    explanation="Recursively walks filesystem — may profile for exfiltration targets.",
    fix="Scope file operations to the skill's own directory."),
  dict(id="SH-010",severity="MEDIUM",language="shell",title="Sensitive env var harvesting",
    pattern=r"\$\{?(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|GH_TOKEN|SECRET_KEY|DATABASE_URL|DB_PASS)",
    applies_to={'shell','markdown','text','dotenv'},
    explanation="Accesses credential env vars — dangerous if forwarded externally.",
    fix="Document required env vars in SKILL.md. Never forward them to external servers."),

  # ── PYTHON ─────────────────────────────────────────
  dict(id="PY-001",severity="HIGH",language="python",title="os.system() with dynamic argument",
    pattern=r"os\.system\s*\(\s*(?!['\"](?:ls|echo|pwd|git|npm|pip)['\"])",
    applies_to={'python'},
    explanation="Dynamic shell execution — command injection if any part is user-controlled.",
    fix="Use subprocess.run(['cmd','arg']) with a fixed list."),
  dict(id="PY-002",severity="HIGH",language="python",title="subprocess shell=True",
    pattern=r"subprocess\.(run|call|check_output|check_call|Popen)\s*\([^)]{0,200}shell\s*=\s*True",
    applies_to={'python'},
    explanation="Routes command through /bin/sh — enables shell injection.",
    fix="Use shell=False and pass a list: subprocess.run(['cmd','arg'])."),
  dict(id="PY-003",severity="HIGH",language="python",title="eval() on non-literal",
    pattern=r"\beval\s*\(\s*(?![\'\"](?:[0-9]|True|False|None|\[|\{))",
    applies_to={'python'},
    explanation="eval() executes arbitrary Python — RCE if source is external.",
    fix="Use ast.literal_eval() or restructure to avoid eval."),
  dict(id="PY-004",severity="HIGH",language="python",title="exec() on dynamic string",
    pattern=r"\bexec\s*\(\s*(?![\'\"])",applies_to={'python'},
    explanation="exec() compiles and runs arbitrary Python strings.",
    fix="Never exec() dynamic or external strings."),
  dict(id="PY-005",severity="HIGH",language="python",title="pickle deserialization",
    pattern=r"pickle\.(loads?|Unpickler)\s*\(",applies_to={'python'},
    explanation="Pickle can execute arbitrary code during deserialization.",
    fix="Use JSON or msgpack for external data."),
  dict(id="PY-006",severity="HIGH",language="python",title="YAML unsafe load",
    pattern=r"yaml\.load\s*\(\s*[^,)]+\s*\)(?!\s*#.*safe)",applies_to={'python'},
    explanation="yaml.load() without SafeLoader can execute embedded Python objects.",
    fix="Replace with yaml.safe_load()."),
  dict(id="PY-007",severity="HIGH",language="python",title="Obfuscated __import__",
    pattern=r"__import__\s*\(\s*['\"](?:os|subprocess|socket|ctypes|importlib)['\"]",
    applies_to={'python'},
    explanation="Hides dangerous imports from code review.",
    fix="Use normal top-level imports."),
  dict(id="PY-008",severity="HIGH",language="python",title="File exfiltration via HTTP POST",
    pattern=r"(requests|urllib|httpx|aiohttp)\.(post|put|patch)\s*\([^)]*open\s*\(",
    applies_to={'python'},
    explanation="Sends local file contents to an external server.",
    fix="Remove outbound file transfer."),
  dict(id="PY-009",severity="HIGH",language="python",title="Reading SSH/credential files",
    pattern=r"open\s*\([^)]*[\\/]\.ssh[\\/]|expanduser\s*\(['\"]~[\\/]\.ssh",
    applies_to={'python'},
    explanation="Opens SSH private keys for potential exfiltration.",
    fix="Remove credential file access."),
  dict(id="PY-010",severity="HIGH",language="python",title="ctypes / cffi native code loading",
    pattern=r"\bctypes\.(CDLL|WinDLL|cdll\.LoadLibrary|windll)|cffi\.FFI\s*\(\s*\)",
    applies_to={'python'},
    explanation="Loads native shared libraries, bypassing Python-level sandboxing.",
    fix="Remove native library loading unless fully documented and essential."),
  dict(id="PY-011",severity="MEDIUM",language="python",title="Undocumented outbound HTTP",
    pattern=r"(requests|urllib\.request|httpx|aiohttp)\.(get|post|put|delete|head|request)\s*\(['\"]https?://",
    applies_to={'python'},
    explanation="Outbound network call — may be telemetry or exfiltration.",
    fix="Document the endpoint and purpose in SKILL.md."),
  dict(id="PY-012",severity="MEDIUM",language="python",title="Home directory file access",
    pattern=r"(expanduser\s*\(['\"]~|os\.environ\[['\"]HOME['\"]|Path\.home\(\))\s*[/+]",
    applies_to={'python'},
    explanation="Accesses files outside the skill's own directory.",
    fix="Scope file access to the skill's working directory."),
  dict(id="PY-013",severity="MEDIUM",language="python",title="importlib dynamic import",
    pattern=r"importlib\.(import_module|util\.spec_from_file_location)\s*\([^'\"()][^)]*\)",
    applies_to={'python'},
    explanation="Loads modules by computed name — may load malicious code.",
    fix="Use static imports. Whitelist allowed module names if dynamic loading is required."),

  # ── JAVASCRIPT / TYPESCRIPT ───────────────────────
  dict(id="JS-001",severity="HIGH",language="javascript",title="eval() on non-literal",
    pattern=r"\beval\s*\(\s*(?!['\"`](?:true|false|\d))",
    applies_to={'javascript','typescript'},
    explanation="eval() executes arbitrary JS — RCE if source is external.",
    fix="Remove eval(). Use JSON.parse() for data."),
  dict(id="JS-002",severity="HIGH",language="javascript",title="child_process exec with dynamic input",
    pattern=r"(?<!\.)(\bexecSync|\bexec)\s*\(\s*(?!['\"`](?:git|npm|node|ls|echo)\b)(?!/\^)",
    applies_to={'javascript','typescript'},
    explanation="Shell execution with dynamic args — command injection. (Excludes regex .exec() calls)",
    fix="Use execFile() or spawn() with fixed command and separate argument array."),
  dict(id="JS-003",severity="HIGH",language="javascript",title="new Function() code injection",
    pattern=r"\bnew\s+Function\s*\(",applies_to={'javascript','typescript'},
    explanation="Constructs executable code from a string — equivalent to eval().",
    fix="Replace with a static function."),
  dict(id="JS-004",severity="HIGH",language="javascript",title="Reading SSH/credential files (Node.js)",
    pattern=r"(readFile|readFileSync|createReadStream)\s*\([^)]*\.ssh[^)]*\)",
    applies_to={'javascript','typescript'},
    explanation="Reads SSH private keys from the filesystem.",
    fix="Remove credential file access."),
  dict(id="JS-005",severity="HIGH",language="javascript",title="Dynamic require() from variable",
    pattern=r"\brequire\s*\(\s*(?!['\"`])",applies_to={'javascript','typescript'},
    explanation="Loads a module whose name is computed — may load attacker-controlled code.",
    fix="Use static require('module-name') string literals."),
  dict(id="JS-006",severity="HIGH",language="javascript",title="vm.runInNewContext / vm.Script",
    pattern=r"\bvm\.(runInNewContext|runInThisContext|Script)\s*\(",
    applies_to={'javascript','typescript'},
    explanation="Executes JS in a V8 VM — sandbox escape is well-documented.",
    fix="Remove vm module usage."),
  dict(id="JS-007",severity="MEDIUM",language="javascript",title="External HTTP POST",
    pattern=r"(fetch|axios\.(post|put)|http\.request)\s*\(\s*['\"]https?://",
    applies_to={'javascript','typescript'},
    explanation="Sends data to an external server — potential exfiltration.",
    fix="Document the endpoint in SKILL.md. Ensure no user data is sent without consent."),
  dict(id="JS-008",severity="MEDIUM",language="javascript",title="process.env credential access",
    pattern=r"process\.env\.[A-Z_]*(SECRET|TOKEN|KEY|PASS|PWD)[A-Z_]*",
    applies_to={'javascript','typescript'},
    explanation="Reads credential env vars — dangerous if forwarded externally.",
    fix="Only read env vars your skill requires. Document them in SKILL.md."),

  # ── RUBY ───────────────────────────────────────────
  dict(id="RB-001",severity="HIGH",language="ruby",title="system()/exec() with dynamic input",
    pattern=r"\b(system|exec|spawn)\s*\(\s*(?!['\"](?:git|gem|bundle|ruby|echo|ls)\b)",
    applies_to={'ruby'},
    explanation="Shell execution with dynamic arguments — injection risk.",
    fix="Use Open3.capture3 with an argument array."),
  dict(id="RB-002",severity="HIGH",language="ruby",title="eval() on non-literal",
    pattern=r"\beval\s*\(\s*(?!['\"])",applies_to={'ruby'},
    explanation="eval() executes arbitrary Ruby code.",
    fix="Remove eval(). Use static logic or a safe DSL."),
  dict(id="RB-003",severity="HIGH",language="ruby",title="require/load from variable",
    pattern=r"\b(require|load|require_relative)\s*\(\s*(?!['\"])",applies_to={'ruby'},
    explanation="Dynamically loads a file by computed path.",
    fix="Use string literals in require/load."),
  dict(id="RB-004",severity="HIGH",language="ruby",title="Shell profile persistence",
    pattern=r"File\.(write|open|append).*\.(bashrc|zshrc|bash_profile)",
    applies_to={'ruby'},
    explanation="Writes to shell startup files — creates persistent code execution.",
    fix="Remove shell profile modifications."),
  dict(id="RB-005",severity="MEDIUM",language="ruby",title="Net::HTTP to external host",
    pattern=r"(Net::HTTP\.get|URI\.open|open-uri)\s*\(['\"]https?://(?!rubygems\.org|api\.github\.com)",
    applies_to={'ruby'},
    explanation="Outbound HTTP to unknown host — potential exfiltration.",
    fix="Document the endpoint in SKILL.md."),
  dict(id="RB-006",severity="HIGH",language="ruby",title="Backtick shell execution",
    pattern=r"`[^`]{5,}`",applies_to={'ruby'},
    explanation="Backtick notation executes shell commands — injection risk with interpolation.",
    fix="Use Open3.capture3 with an explicit argument array."),

  # ── PHP ────────────────────────────────────────────
  dict(id="PHP-001",severity="HIGH",language="php",title="exec()/system()/passthru() with variable",
    pattern=r"\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$",
    applies_to={'php'},
    explanation="PHP command execution with user-influenced variable — injection risk.",
    fix="Use escapeshellarg() and prefer parameterised APIs."),
  dict(id="PHP-002",severity="HIGH",language="php",title="eval() on dynamic string",
    pattern=r"\beval\s*\(\s*(?!['\"])",applies_to={'php'},
    explanation="eval() executes arbitrary PHP.",
    fix="Remove eval()."),
  dict(id="PHP-003",severity="HIGH",language="php",title="include/require from variable",
    pattern=r"\b(include|require|include_once|require_once)\s*\(\s*\$",
    applies_to={'php'},
    explanation="Remote/local file inclusion — loads attacker-controlled PHP.",
    fix="Use whitelisted string literals for include paths."),
  dict(id="PHP-004",severity="HIGH",language="php",title="file_get_contents with remote URL",
    pattern=r"file_get_contents\s*\(\s*['\"]https?://",applies_to={'php'},
    explanation="Fetches remote content — can load and execute remote payloads.",
    fix="Download only from allowlisted, verified URLs."),
  dict(id="PHP-005",severity="HIGH",language="php",title="Obfuscated PHP base64 eval",
    pattern=r"eval\s*\(\s*base64_decode\s*\(",applies_to={'php'},
    explanation="Classic PHP webshell — executes base64-encoded arbitrary PHP.",
    fix="Remove entirely. This has no legitimate use."),

  # ── GO ─────────────────────────────────────────────
  dict(id="GO-001",severity="HIGH",language="go",title="exec.Command with shell interpreter",
    pattern=r'exec\.Command\s*\(\s*"(sh|bash|zsh|cmd\.exe|powershell)"',
    applies_to={'go'},
    explanation="Spawns a shell — enables injection with dynamic arguments.",
    fix="Use exec.Command with the real binary and separate .Arg() calls."),
  dict(id="GO-002",severity="HIGH",language="go",title="os.OpenFile/ReadFile on sensitive path",
    pattern=r'os\.(Open|OpenFile|ReadFile)\s*\(\s*"/(etc|root|home/\w+/\.ssh)',
    applies_to={'go'},
    explanation="Opens sensitive system or credential files.",
    fix="Restrict file access to the skill's working directory."),
  dict(id="GO-003",severity="MEDIUM",language="go",title="plugin.Open dynamic code loading",
    pattern=r"\bplugin\.Open\s*\(",applies_to={'go'},
    explanation="Loads a compiled Go plugin (.so) at runtime — can load malicious shared libs.",
    fix="Avoid plugin loading. Compile all required functionality statically."),
  dict(id="GO-004",severity="MEDIUM",language="go",title="Outbound HTTP to external host",
    pattern=r'http\.(Get|Post|Do)\s*\(\s*"https?://(?!pkg\.go\.dev|sum\.golang\.org|proxy\.golang\.org)',
    applies_to={'go'},
    explanation="Outbound network call to non-Go-infrastructure host.",
    fix="Document the endpoint in SKILL.md."),
  dict(id="GO-005",severity="HIGH",language="go",title="exec.Command with variable (non-literal) command",
    pattern=r"exec\.Command\s*\(\s*(?!\")",
    applies_to={'go'},
    explanation="Command name is dynamic — injection risk if user-controlled.",
    fix="Use a string literal for the binary name; pass dynamic values as separate .Arg() calls."),
  dict(id="GO-006",severity="HIGH",language="go",title="Shell -c flag enables command injection",
    pattern=r'exec\.Command\s*\([^)]+"-c"\s*,',
    applies_to={'go'},
    explanation="Passing -c to a shell interpreter enables full command injection.",
    fix="Build the argument list explicitly without -c."),
  dict(id="GO-007",severity="HIGH",language="go",title="net.Dial TCP to external host",
    pattern=r'net\.Dial\s*\(\s*"tcp"\s*,\s*(?!"localhost|127\.0\.0\.1")',
    applies_to={'go'},
    explanation="Opens TCP connection to external host — may establish C2 or reverse shell.",
    fix="Document all outbound TCP connections in SKILL.md."),
  dict(id="GO-008",severity="HIGH",language="go",title="WriteFile to system directory",
    pattern=r'(ioutil\.WriteFile|os\.WriteFile)\s*\(\s*"/(etc|usr|bin|sbin|lib)',
    applies_to={'go'},
    explanation="Writes to OS system directories — potential backdoor.",
    fix="Write only to /tmp or the skill's own working directory."),
  dict(id="GO-009",severity="HIGH",language="go",title="os.Setenv tampering with PATH/LD_PRELOAD",
    pattern=r'os\.Setenv\s*\(\s*"(PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)"',
    applies_to={'go'},
    explanation="Modifying PATH or LD_PRELOAD enables DLL/binary hijacking.",
    fix="Remove environment variable tampering."),
  dict(id="GO-010",severity="MEDIUM",language="go",title="filepath.Walk on home directory",
    pattern=r'filepath\.(Walk|WalkDir)\s*\(\s*(?:os\.Getenv\s*\(\s*"HOME"\s*\)|os\.UserHomeDir\s*\(\s*\))',
    applies_to={'go'},
    explanation="Recursively enumerates home directory — may profile for exfiltration.",
    fix="Scope file operations to the skill's own directory."),

  # ── RUST ───────────────────────────────────────────
  dict(id="RS-001",severity="HIGH",language="rust",title="Command::new with shell interpreter",
    pattern=r'Command::new\s*\(\s*"(sh|bash|zsh|cmd|powershell)"',
    applies_to={'rust'},
    explanation="Spawns a shell — enables injection if arguments are dynamic.",
    fix="Use Command::new with the real binary and .arg() for each argument."),
  dict(id="RS-002",severity="HIGH",language="rust",title="unsafe block",
    pattern=r"\bunsafe\s*\{",applies_to={'rust'},
    explanation="Bypasses Rust's memory safety guarantees — can enable exploits.",
    fix="Minimize unsafe blocks. Document exactly why each is needed."),
  dict(id="RS-003",severity="MEDIUM",language="rust",title="libloading dynamic library",
    pattern=r"libloading::(Library|Symbol)",applies_to={'rust'},
    explanation="Loads native .so/.dll at runtime — can load malicious native code.",
    fix="Avoid dynamic library loading in skill scripts."),
  dict(id="RS-004",severity="HIGH",language="rust",title="Command::new with variable (non-literal)",
    pattern=r"Command::new\s*\(\s*(?!\")",
    applies_to={'rust'},
    explanation="Binary path is dynamic — binary substitution attack if user-controlled.",
    fix="Use a string literal for the binary name."),
  dict(id="RS-005",severity="HIGH",language="rust",title="std::fs read of SSH/credential files",
    pattern=r'fs::(read|read_to_string)\s*\(\s*"[^"]*(\.ssh|/etc/(passwd|shadow|sudoers))',
    applies_to={'rust'},
    explanation="Reads SSH keys or system credential files.",
    fix="Remove credential file access."),
  dict(id="RS-006",severity="HIGH",language="rust",title="std::fs write to system directories",
    pattern=r'fs::(write|File::create)\s*\(\s*"/(etc|usr|bin|sbin|lib)',
    applies_to={'rust'},
    explanation="Writes to OS system directories — potential backdoor.",
    fix="Write only to /tmp or the skill's working directory."),
  dict(id="RS-007",severity="HIGH",language="rust",title="std::env::set_var PATH/LD_PRELOAD",
    pattern=r'env::set_var\s*\(\s*"(PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)"',
    applies_to={'rust'},
    explanation="Modifies PATH or LD_PRELOAD — enables binary/DLL hijacking.",
    fix="Remove environment variable tampering."),
  dict(id="RS-008",severity="MEDIUM",language="rust",title="reqwest/ureq POST to external URL",
    pattern=r'(reqwest|ureq)::(blocking::)?Client|reqwest::get\s*\(\s*"https?://(?!crates\.io|docs\.rs)',
    applies_to={'rust'},
    explanation="Outbound HTTP request — may be exfiltration or C2 channel.",
    fix="Document the endpoint in SKILL.md."),
  dict(id="RS-009",severity="MEDIUM",language="rust",title="std::process::exit with non-zero code",
    pattern=r"process::exit\s*\(\s*(?!0\s*\))",
    applies_to={'rust'},
    explanation="Abnormal process termination may mask errors or prevent cleanup.",
    fix="Use Result/? for error propagation instead of abrupt exit."),

  # ── POWERSHELL ─────────────────────────────────────
  dict(id="PS-001",severity="HIGH",language="powershell",title="Invoke-Expression (IEX)",
    pattern=r"(?i)(Invoke-Expression|IEX)\s*\(",
    applies_to={'powershell','text','markdown'},
    explanation="PowerShell eval() — executes arbitrary commands from strings.",
    fix="Remove IEX. Use named cmdlets with static parameters."),
  dict(id="PS-002",severity="HIGH",language="powershell",title="Download-and-execute",
    pattern=r"(?i)(DownloadString|Invoke-WebRequest[^;]+\|\s*IEX|iwr[^;]+\|\s*iex)",
    applies_to={'powershell','markdown','text'},
    explanation="Downloads and immediately executes remote PowerShell — top malware delivery method.",
    fix="Download to a file, inspect, then execute only verified content."),
  dict(id="PS-003",severity="HIGH",language="powershell",title="Bypass execution policy",
    pattern=r"(?i)-ExecutionPolicy\s+(Bypass|Unrestricted)|Set-ExecutionPolicy\s+(Bypass|Unrestricted)",
    applies_to={'powershell','markdown'},
    explanation="Disables PowerShell's built-in execution restrictions.",
    fix="Do not bypass execution policy."),
  dict(id="PS-004",severity="HIGH",language="powershell",title="Credential / SecureString access",
    pattern=r"(?i)(Get-Credential|ConvertTo-SecureString|SecureString|GetNetworkCredential)",
    applies_to={'powershell'},
    explanation="Accesses or manipulates credentials in memory.",
    fix="Remove credential manipulation."),
  dict(id="PS-005",severity="HIGH",language="powershell",title="Registry modification",
    pattern=r"(?i)(Set-ItemProperty|New-ItemProperty|HKCU:|HKLM:|HKEY_)",
    applies_to={'powershell'},
    explanation="Modifies Windows Registry — can create persistence or change system behavior.",
    fix="Remove registry modifications."),
  dict(id="PS-006",severity="MEDIUM",language="powershell",title="Encoded command (-EncodedCommand)",
    pattern=r"(?i)-En(coded)?C(ommand)?\s+[A-Za-z0-9+/=]{20,}",
    applies_to={'powershell','markdown','text'},
    explanation="Hides actual command in Base64 — common obfuscation technique.",
    fix="Decode and audit. Replace with plaintext commands."),

  # ── JAVA / KOTLIN ──────────────────────────────────
  dict(id="JV-001",severity="HIGH",language="java",title="Runtime.exec() with dynamic command",
    pattern=r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?!['\"](?:git|java|mvn))",
    applies_to={'java','kotlin'},
    explanation="Shell execution with dynamic command string — injection risk.",
    fix="Use ProcessBuilder with a list of arguments."),
  dict(id="JV-002",severity="HIGH",language="java",title="Reflection to invoke arbitrary methods",
    pattern=r"Class\.forName\s*\([^)]*\)\.getMethod|getDeclaredMethod\s*\(\s*(?!['\"](?:get|set|is))",
    applies_to={'java','kotlin'},
    explanation="Dynamically invokes methods — may bypass access controls.",
    fix="Use static method calls where possible."),
  dict(id="JV-003",severity="HIGH",language="java",title="Java ObjectInputStream deserialization",
    pattern=r"new\s+ObjectInputStream\s*\(",applies_to={'java','kotlin'},
    explanation="Java native deserialization can execute arbitrary code.",
    fix="Use JSON/Protobuf/XML. Never deserialize untrusted Java objects."),
  dict(id="JV-004",severity="HIGH",language="java",title="URLClassLoader remote class loading",
    pattern=r"new\s+URLClassLoader\s*\(",applies_to={'java','kotlin'},
    explanation="Loads compiled Java classes from a URL — attacker can supply malicious JAR.",
    fix="Remove remote class loading. Package all dependencies locally."),
  dict(id="JV-005",severity="MEDIUM",language="java",title="Outbound HTTP to external host",
    pattern=r"new\s+URL\s*\(\s*['\"]https?://(?!repo1\.maven\.org|repo\.maven\.apache\.org)",
    applies_to={'java','kotlin'},
    explanation="Connects to an external host — potential exfiltration.",
    fix="Document the endpoint in SKILL.md."),

  # ── SWIFT ──────────────────────────────────────────
  dict(id="SW-001",severity="HIGH",language="swift",title="Process/NSTask shell execution",
    pattern=r"(Process|NSTask)\s*\(\s*\)|\.launchPath\s*=\s*\"/bin/(sh|bash|zsh)\"",
    applies_to={'swift'},
    explanation="Spawns a shell process — dynamic arguments enable injection.",
    fix="Set launchPath to the specific binary. Pass arguments as an array."),
  dict(id="SW-002",severity="HIGH",language="swift",title="Keychain access",
    pattern=r"(SecItemCopyMatching|SecKeychainFindGenericPassword|kSecClass)",
    applies_to={'swift'},
    explanation="Reads macOS/iOS Keychain — may access saved passwords and certificates.",
    fix="Remove keychain access. Skills must not access user credentials."),
  dict(id="SW-003",severity="HIGH",language="swift",title="FileManager reading SSH/credential files",
    pattern=r'FileManager|contentsOfFile.*\.ssh|String\s*\(contentsOfFile.*\.aws',
    applies_to={'swift'},
    explanation="Reads SSH keys or cloud credential files via FileManager.",
    fix="Remove credential file access."),
  dict(id="SW-004",severity="HIGH",language="swift",title="URLSession data exfiltration",
    pattern=r"URLSession\.shared\.(dataTask|uploadTask)\s*\(with",
    applies_to={'swift'},
    explanation="Sends data via URLSession — may exfiltrate local files or credentials.",
    fix="Document any network calls in SKILL.md. Ensure no user data is sent without consent."),
  dict(id="SW-005",severity="HIGH",language="swift",title="Dynamic library injection (dlopen)",
    pattern=r"\bdlopen\s*\(|NSBundle\.load\b",
    applies_to={'swift'},
    explanation="Loads a native dynamic library at runtime — can load malicious native code.",
    fix="Remove dynamic library loading."),
  dict(id="SW-006",severity="HIGH",language="swift",title="Arbitrary code execution via NSTask arguments",
    pattern=r"\.arguments\s*=\s*\[.*\$",
    applies_to={'swift'},
    explanation="Interpolates variables into task arguments — command injection risk.",
    fix="Use hard-coded string literals for all task arguments."),
  dict(id="SW-007",severity="MEDIUM",language="swift",title="UserDefaults storing sensitive data",
    pattern=r"UserDefaults\.standard\.set\s*\([^,)]*(?i:password|token|secret|key)",
    applies_to={'swift'},
    explanation="UserDefaults is unencrypted plist storage — credentials stored here are easily readable.",
    fix="Use Keychain for sensitive data storage (and document why it's needed)."),
  dict(id="SW-008",severity="MEDIUM",language="swift",title="Notification Center posting system events",
    pattern=r"NotificationCenter\.default\.post.*name.*\.NSWorkspace|NSRunningApplication",
    applies_to={'swift'},
    explanation="Posts system-level notifications that could interfere with other applications.",
    fix="Restrict notifications to your own app's domain."),

  # ── LUA ────────────────────────────────────────────
  dict(id="LU-001",severity="HIGH",language="lua",title="os.execute() with dynamic command",
    pattern=r"\bos\.execute\s*\(\s*(?!['\"](?:ls|echo|pwd))",
    applies_to={'lua'},
    explanation="Executes shell commands from Lua — injection risk with dynamic input.",
    fix="Use a fixed command string. Never pass user input to os.execute()."),
  dict(id="LU-002",severity="HIGH",language="lua",title="loadstring()/load() on dynamic content",
    pattern=r"\b(loadstring|load)\s*\(\s*(?!['\"])",
    applies_to={'lua'},
    explanation="Lua eval() — executes dynamically constructed code.",
    fix="Remove loadstring/load."),
  dict(id="LU-003",severity="MEDIUM",language="lua",title="require() from variable",
    pattern=r"\brequire\s*\(\s*(?!['\"])",applies_to={'lua'},
    explanation="Loads a module whose name is computed — may load attacker-supplied code.",
    fix="Use string literals in require() calls."),
  dict(id="LU-004",severity="HIGH",language="lua",title="io.popen() shell command",
    pattern=r"\bio\.popen\s*\(\s*(?!['\"](?:ls|echo|date))",
    applies_to={'lua'},
    explanation="io.popen() opens a shell pipeline — injection risk if argument is dynamic.",
    fix="Use a fixed string literal. Never pass user input to io.popen()."),
  dict(id="LU-005",severity="HIGH",language="lua",title="Reading credential files via io.open",
    pattern=r"io\.open\s*\([^)]*[\\/]\.ssh[\\/]|/etc/(passwd|shadow)",
    applies_to={'lua'},
    explanation="Opens SSH keys or system credential files.",
    fix="Remove credential file access."),
  dict(id="LU-006",severity="HIGH",language="lua",title="dofile()/loadfile() from variable path",
    pattern=r"\b(dofile|loadfile)\s*\(\s*(?!['\"])",
    applies_to={'lua'},
    explanation="Executes a Lua file from a dynamic path — may load attacker-supplied scripts.",
    fix="Use string literals for file paths in dofile/loadfile."),
  dict(id="LU-007",severity="MEDIUM",language="lua",title="HTTP request via socket/luasocket",
    pattern=r"(socket\.http|require\s*\(\s*['\"]socket\.http['\"]|luasocket)",
    applies_to={'lua'},
    explanation="Makes outbound HTTP request — may be exfiltration or C2.",
    fix="Document the endpoint in SKILL.md."),
  dict(id="LU-008",severity="MEDIUM",language="lua",title="pcall hiding errors on sensitive operations",
    pattern=r"pcall\s*\(\s*(os\.execute|io\.popen|loadstring)",
    applies_to={'lua'},
    explanation="pcall wrapping dangerous functions silences errors — hides failed exploits.",
    fix="Remove pcall wrapping of command execution functions."),

  # ── R ──────────────────────────────────────────────
  dict(id="R-001",severity="HIGH",language="r",title="system()/system2() with dynamic command",
    pattern=r"\bsystem(2)?\s*\(\s*(?!['\"](?:ls|echo|Rscript|git))",
    applies_to={'r'},
    explanation="Shell execution with dynamic args in R — command injection.",
    fix="Use processx::run() with separate command and args. Validate all inputs."),
  dict(id="R-002",severity="HIGH",language="r",title="eval(parse()) on external string",
    pattern=r"\beval\s*\(\s*parse\s*\(\s*text\s*=",applies_to={'r'},
    explanation="Executes arbitrary R code from a string — R equivalent of exec().",
    fix="Remove eval(parse()). Use static function calls."),
  dict(id="R-003",severity="HIGH",language="r",title="Reading SSH/credential files via readLines/file",
    pattern=r"(readLines|file|readChar)\s*\([^)]*(\.ssh|/etc/passwd|\.aws/credentials)",
    applies_to={'r'},
    explanation="Reads SSH keys or cloud credentials from disk.",
    fix="Remove credential file access entirely."),
  dict(id="R-004",severity="HIGH",language="r",title="Downloading and sourcing remote R script",
    pattern=r"(source|eval\s*\(\s*parse)\s*\([^)]*https?://",
    applies_to={'r'},
    explanation="Downloads and executes a remote R script — RCE vector.",
    fix="Download to a local file, review, then source only trusted content."),
  dict(id="R-005",severity="HIGH",language="r",title="Sys.setenv modifying PATH/LD_PRELOAD",
    pattern=r"Sys\.setenv\s*\(\s*(PATH|LD_PRELOAD|LD_LIBRARY_PATH)\s*=",
    applies_to={'r'},
    explanation="Modifies PATH or LD_PRELOAD — enables binary/DLL hijacking.",
    fix="Remove environment variable tampering."),
  dict(id="R-006",severity="HIGH",language="r",title="serialize/unserialize of external data",
    pattern=r"\bunserialize\s*\(",applies_to={'r'},
    explanation="R deserialization can execute arbitrary code — equivalent to Python pickle.",
    fix="Use JSON or CSV for data exchange. Never unserialize untrusted R objects."),
  dict(id="R-007",severity="MEDIUM",language="r",title="Outbound HTTP via httr/curl/RCurl",
    pattern=r"(httr::(GET|POST|PUT)|curl::curl_fetch|RCurl::getURL)\s*\(['\"]https?://",
    applies_to={'r'},
    explanation="Outbound network call — may be exfiltration or telemetry.",
    fix="Document the endpoint and purpose in SKILL.md."),
  dict(id="R-008",severity="MEDIUM",language="r",title="write to home directory or /tmp",
    pattern=r"(write\.csv|write\.table|saveRDS|save)\s*\([^,)]+,\s*['\"]~|Sys\.getenv\s*\(['\"]HOME['\"]\)",
    applies_to={'r'},
    explanation="Writes files to the user home directory outside the skill's scope.",
    fix="Restrict file output to the skill's own working directory."),

  # ── SQL ────────────────────────────────────────────
  dict(id="SQL-001",severity="HIGH",language="sql",title="Dynamic SQL via EXEC/@variable",
    pattern=r"(?i)\b(EXEC|EXECUTE|sp_executesql)\s*\(\s*@",
    applies_to={'sql'},
    explanation="Executes SQL built from a variable — injection if user-controlled.",
    fix="Use parameterised queries with fixed SQL text."),
  dict(id="SQL-002",severity="HIGH",language="sql",title="xp_cmdshell OS execution",
    pattern=r"(?i)xp_cmdshell",applies_to={'sql'},
    explanation="SQL Server feature executing OS commands — critical attack vector.",
    fix="Disable xp_cmdshell. Never use in skill scripts."),
  dict(id="SQL-003",severity="MEDIUM",language="sql",title="LOAD DATA / BULK INSERT from file",
    pattern=r"(?i)(LOAD\s+DATA\s+(LOCAL\s+)?INFILE|BULK\s+INSERT)\s+['\"]\/",
    applies_to={'sql'},
    explanation="Reads from server filesystem — may expose sensitive data.",
    fix="Restrict file paths to known, safe locations."),
  dict(id="SQL-004",severity="HIGH",language="sql",title="DROP TABLE / DROP DATABASE",
    pattern=r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
    applies_to={'sql'},
    explanation="Destructively drops database objects — may be data destruction payload.",
    fix="Remove destructive DDL. If migration needed, document explicitly and require confirmation."),
  dict(id="SQL-005",severity="HIGH",language="sql",title="TRUNCATE TABLE",
    pattern=r"(?i)\bTRUNCATE\s+TABLE\b",
    applies_to={'sql'},
    explanation="Deletes all rows from a table — potential destructive payload.",
    fix="Remove TRUNCATE. If data cleanup is needed, use scoped DELETE with a WHERE clause."),
  dict(id="SQL-006",severity="HIGH",language="sql",title="GRANT ALL PRIVILEGES",
    pattern=r"(?i)\bGRANT\s+ALL\s+PRIVILEGES\b",
    applies_to={'sql'},
    explanation="Grants full database access — privilege escalation.",
    fix="Grant only the minimum required permissions."),
  dict(id="SQL-007",severity="HIGH",language="sql",title="INTO OUTFILE / INTO DUMPFILE",
    pattern=r"(?i)\bINTO\s+(OUTFILE|DUMPFILE)\b",
    applies_to={'sql'},
    explanation="MySQL feature to write query results to the server filesystem — may write webshells.",
    fix="Remove INTO OUTFILE/DUMPFILE usage."),
  dict(id="SQL-008",severity="MEDIUM",language="sql",title="CREATE TRIGGER with EXECUTE",
    pattern=r"(?i)\bCREATE\s+(OR\s+REPLACE\s+)?TRIGGER\b[^;]+\bEXECUTE\b",
    applies_to={'sql'},
    explanation="Database trigger that executes code on data changes — can create persistent payload.",
    fix="Remove trigger creation. Document any required triggers in SKILL.md."),
  dict(id="SQL-009",severity="MEDIUM",language="sql",title="CREATE USER / ALTER USER",
    pattern=r"(?i)\b(CREATE|ALTER)\s+USER\b",
    applies_to={'sql'},
    explanation="Creates or modifies database users — may create backdoor accounts.",
    fix="Remove user management SQL. Provide instructions for manual setup instead."),

  # ── DOCKERFILE ────────────────────────────────────
  dict(id="DF-001",severity="HIGH",language="dockerfile",title="RUN pipe-to-shell",
    pattern=r"RUN\s+.*(curl|wget)\s+[^\|]+\|\s*(ba)?sh",
    applies_to={'dockerfile','text'},
    explanation="Downloads and executes a remote script in the container build.",
    fix="Download to a file, verify a checksum, then execute."),
  dict(id="DF-002",severity="MEDIUM",language="dockerfile",title="ADD with remote URL",
    pattern=r"^ADD\s+https?://",applies_to={'dockerfile'},
    explanation="ADD with URL fetches remote content without integrity verification.",
    fix="Use RUN curl with --fail and a checksum verification step."),
  dict(id="DF-003",severity="MEDIUM",language="dockerfile",title="Secret in ENV/ARG",
    pattern=r"(?i)(ENV|ARG)\s+\w*(TOKEN|SECRET|PASSWORD|KEY|PWD)\w*\s*=\s*\S+",
    applies_to={'dockerfile'},
    explanation="Secrets baked into image layers are readable by anyone with image access.",
    fix="Pass secrets at runtime via --env or Docker secrets, not in Dockerfile."),
  dict(id="DF-004",severity="HIGH",language="dockerfile",title="Running container as root (no USER directive)",
    pattern=r"^(?!.*\bUSER\b)FROM\s+",
    applies_to={'dockerfile'},
    explanation="Container running as root amplifies the impact of any exploit.",
    fix="Add USER <nonroot> before CMD/ENTRYPOINT."),
  dict(id="DF-005",severity="HIGH",language="dockerfile",title="Privileged capability (--privileged or SYS_ADMIN)",
    pattern=r"(?i)(--privileged|CAP_SYS_ADMIN|CAP_NET_ADMIN|--cap-add\s+ALL)",
    applies_to={'dockerfile'},
    explanation="Grants container near-root access to the host system.",
    fix="Remove privileged flags. Use only the minimum capabilities required."),
  dict(id="DF-006",severity="HIGH",language="dockerfile",title="Mounting host filesystem (--volume /)",
    pattern=r"VOLUME\s+['\"]?/(etc|proc|sys|dev|run|host)\b",
    applies_to={'dockerfile'},
    explanation="Mounts sensitive host directories into the container — enables host escape.",
    fix="Never mount host system directories. Use named volumes only."),
  dict(id="DF-007",severity="MEDIUM",language="dockerfile",title="curl/wget with --insecure / -k flag",
    pattern=r"(curl|wget)\s+.*(--insecure|-k)\b",
    applies_to={'dockerfile'},
    explanation="Disables TLS certificate verification — enables MITM attacks during download.",
    fix="Remove --insecure/-k. Fix the certificate or use a proper CA bundle."),
  dict(id="DF-008",severity="MEDIUM",language="dockerfile",title="Exposing sensitive port (22/3306/5432/6379)",
    pattern=r"EXPOSE\s+(22|3306|5432|6379|27017|1521)\b",
    applies_to={'dockerfile'},
    explanation="Exposes database/SSH ports that may be unintentionally accessible.",
    fix="Expose only ports required by the skill. Never expose SSH in a skill container."),
  dict(id="DF-009",severity="LOW",language="dockerfile",title="Using latest tag for base image",
    pattern=r"FROM\s+[^:@\s]+:latest\b",
    applies_to={'dockerfile'},
    explanation="latest tag may silently pull a different (potentially compromised) image.",
    fix="Pin to a specific image digest: FROM image@sha256:... or FROM image:1.2.3"),

  # ── .env / config ──────────────────────────────────
  dict(id="ENV-001",severity="HIGH",language="dotenv",title="Hardcoded secret in config file",
    pattern=r"(?i)(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)\s*=\s*(?!your_|<|CHANGE|PLACEHOLDER|\$\{)[A-Za-z0-9_\-\.\/+]{8,}",
    applies_to={'dotenv','ini','text'},
    explanation="Real credentials committed to skill package — exposed to all installers.",
    fix="Replace with placeholders. Instruct users to supply their own values."),
  dict(id="ENV-002",severity="MEDIUM",language="dotenv",title="DB connection string with credentials",
    pattern=r"(?i)(DATABASE_URL|DB_URL|MONGO_URL|REDIS_URL)\s*=\s*(mongodb|postgres|mysql|redis):\/\/[^:@\s]+:[^@\s]+@",
    applies_to={'dotenv','ini','text'},
    explanation="Database URL contains embedded credentials.",
    fix="Use separate DB_USER/DB_PASS variables with placeholder values."),
  dict(id="ENV-003",severity="HIGH",language="dotenv",title="Private key PEM block in config",
    pattern=r"-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PRIVATE)\s+PRIVATE\s+KEY-----",
    applies_to={'dotenv','ini','text','markdown'},
    explanation="PEM-encoded private key embedded directly in a config/doc file.",
    fix="Remove the private key entirely. Never commit private keys."),
  dict(id="ENV-004",severity="HIGH",language="dotenv",title="Cloud service credentials pattern",
    pattern=r"(?i)(AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+)",
    applies_to={'dotenv','ini','text'},
    explanation="Matches AWS Access Key ID (AKIA...), Google API Key (AIza...), or Google OAuth token (ya29...).",
    fix="Revoke the exposed key immediately and replace with a placeholder."),
  dict(id="ENV-005",severity="HIGH",language="dotenv",title="Slack/Discord/Telegram bot token",
    pattern=r"(xox[baprs]-[0-9A-Za-z-]{10,}|https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|[0-9]{8,10}:[A-Za-z0-9_-]{35})",
    applies_to={'dotenv','ini','text'},
    explanation="Hardcoded messaging platform bot token — allows impersonation of the bot.",
    fix="Revoke and rotate the token. Use an environment variable placeholder."),
  dict(id="ENV-006",severity="MEDIUM",language="dotenv",title="Debug mode enabled in production config",
    pattern=r"(?i)(DEBUG|FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG)\s*=\s*(true|1|yes|on)",
    applies_to={'dotenv','ini'},
    explanation="Debug mode exposes stack traces and internal state to anyone who triggers an error.",
    fix="Set DEBUG=false in production configs."),
  dict(id="ENV-007",severity="MEDIUM",language="dotenv",title="Insecure CORS or allowed hosts wildcard",
    pattern=r"(?i)(ALLOWED_HOSTS|CORS_ORIGIN|ACCESS_CONTROL_ALLOW_ORIGIN)\s*=\s*(\*|0\.0\.0\.0)",
    applies_to={'dotenv','ini'},
    explanation="Wildcard allowed hosts/CORS enables cross-site attacks from any origin.",
    fix="Restrict to specific known hosts."),

  # ── requirements.txt / package.json ───────────────
  dict(id="PKG-001",severity="HIGH",language="requirements",title="Dependency from URL/VCS",
    pattern=r"^\s*(git\+https?://[^\s]+\.git|svn\+https?://|hg\+https?://)",
    applies_to={'requirements'},
    explanation="Installs from arbitrary URL or git repo — no integrity guarantee.",
    fix="Publish to PyPI/npm and pin an exact version."),
  dict(id="PKG-002",severity="LOW",language="requirements",title="Unpinned dependency version",
    pattern=r"^[a-zA-Z0-9_\-]+\s*(>=\s*\d|\*|$)",
    applies_to={'requirements'},
    explanation="Unpinned deps may auto-install a maliciously updated version.",
    fix="Pin exact versions: package==1.2.3"),
  dict(id="PKG-003",severity="HIGH",language="packagejson",title="npm lifecycle pipe-to-shell",
    pattern=r"\"(preinstall|install|postinstall)\"\s*:\s*\"[^\"]*(?:curl|wget)[^\"]*\|\s*(?:ba)?sh",
    applies_to={'packagejson'},
    explanation="npm lifecycle script downloads and executes remote code on every install.",
    fix="Remove remote execution from npm scripts."),
  dict(id="PKG-004",severity="HIGH",language="packagejson",title="npm lifecycle with eval/exec",
    pattern=r"\"(preinstall|install|postinstall)\"\s*:\s*\"[^\"]*(?:node\s+-e|eval|IEX)",
    applies_to={'packagejson'},
    explanation="npm lifecycle executes dynamic code on every install — RCE vector.",
    fix="Remove eval/exec from npm scripts."),
  dict(id="PKG-005",severity="HIGH",language="packagejson",title="Dependency from git URL",
    pattern=r"\"[^\"\.]+\"\s*:\s*\"(git\+https?://|github:|bitbucket:|gitlab:)[^\"]+\"",
    applies_to={'packagejson'},
    explanation="npm dependency resolved from a git URL — no npm audit coverage, integrity not enforced.",
    fix="Publish to npm registry and use a pinned semver version."),
  dict(id="PKG-006",severity="HIGH",language="packagejson",title="Dependency from file/link path",
    pattern=r"\"[^\"\.]+\"\s*:\s*\"(file:|link:)[^\"]+\"",
    applies_to={'packagejson'},
    explanation="Dependency from a local path — bypasses npm integrity checks entirely.",
    fix="Publish to npm and use a versioned reference."),
  dict(id="PKG-007",severity="MEDIUM",language="packagejson",title="Wildcard (*) dependency version",
    pattern=r"\"[a-zA-Z0-9@/_-]+\"\s*:\s*\"\*\"",
    applies_to={'packagejson'},
    explanation="Wildcard versions allow any version to be installed, including compromised ones.",
    fix="Pin exact versions: \"1.2.3\" or use lockfile (package-lock.json/yarn.lock)."),
  dict(id="PKG-008",severity="MEDIUM",language="packagejson",title="Script using rm -rf",
    pattern=r"\"(prebuild|build|clean|prepare)\"\s*:\s*\"[^\"]*rm\s+-rf",
    applies_to={'packagejson'},
    explanation="npm script deletes files with rm -rf — may accidentally wipe unintended directories.",
    fix="Scope the path carefully. Use a library like rimraf with explicit target directories."),

  # ── MARKDOWN / SKILL.md prompt injection ──────────
  dict(id="MD-001",severity="HIGH",language="markdown",title="Prompt injection: override instructions",
    pattern=r"(?i)(ignore\s+(previous|prior|all)\s+instructions|disregard\s+(your\s+)?guidelines|override\s*:|you\s+are\s+now\s+a\s+different\s+AI)",
    applies_to={'markdown','text'},
    explanation="Attempts to hijack Claude's system instructions.",
    fix="Remove all prompt injection attempts."),
  dict(id="MD-002",severity="HIGH",language="markdown",title="Prompt injection: false authority",
    pattern=r"(?i)(anthropic\s+has\s+authorized|as\s+your\s+(developer|creator|maker|owner)|special\s+(override|bypass)\s+code|SYSTEM\s*OVERRIDE)",
    applies_to={'markdown','text'},
    explanation="Claims false authority to bypass Claude's safety guidelines.",
    fix="Remove authority claims."),
  dict(id="MD-003",severity="HIGH",language="markdown",title="Instruction to hide behavior",
    pattern=r"(?i)(do\s+not\s+(tell|show|inform|reveal|disclose)\s+(the\s+)?(user|human)|never\s+mention\s+this\s+(to|instruction)|keep\s+this\s+(secret|hidden|confidential))",
    applies_to={'markdown','text'},
    explanation="Instructs Claude to deceive the user — key indicator of malicious intent.",
    fix="Remove all secrecy instructions."),
  dict(id="MD-004",severity="MEDIUM",language="markdown",title="Hidden HTML comment with behavioral instructions",
    pattern=r"(?i)<!--[^>]*(ignore|disregard|override|you\s+are|do\s+not\s+tell|secret|hidden|system\s+prompt|new\s+instruction|anthropic)[^>]*-->",
    applies_to={'markdown'},
    explanation="HTML comment containing behavioral/instructional keywords — may hide prompt injection.",
    fix="Review and remove if it contains instructions trying to influence Claude's behavior."),
  dict(id="MD-005",severity="MEDIUM",language="markdown",title="Suspicious Unicode control characters",
    pattern="[\u200b\u200c\u200d\ufeff\u202a-\u202e\u2060-\u2064]",
    applies_to={'markdown','text','html'},
    explanation="Invisible Unicode can hide text from visual inspection.",
    fix="Remove all invisible Unicode characters."),

  # ── CROSS-CUTTING: Obfuscation ─────────────────────
  dict(id="OB-001",severity="HIGH",language="general",title="Base64 decode piped to shell",
    pattern=r"base64\s*(-d|--decode)[^|]*\|\s*(ba)?sh|b64decode[^)]*\)\s*\.\s*decode[^)]*\)\s*[\|,].*exec|atob\s*\([^)]+\)\s*[;,]\s*eval",
    applies_to=None,
    explanation="Decodes base64 and executes result — hides real payload from inspection.",
    fix="Decode and audit the content. Replace with a plain, documented command."),
  dict(id="OB-002",severity="HIGH",language="general",title="Eval of base64-decoded string",
    pattern=r"(?i)(eval|exec|IEX)\s*\(\s*(base64|b64|atob|FromBase64String)",
    applies_to=None,
    explanation="Evaluates base64-decoded content — classic malware obfuscation.",
    fix="Decode and audit. Replace with the actual command."),
  dict(id="OB-003",severity="MEDIUM",language="general",title="Long hex-encoded string",
    pattern=r"(\\x[0-9a-fA-F]{2}){6,}",applies_to=None,
    explanation="Long hex sequences may encode dangerous commands.",
    fix="Decode and verify the string is safe."),
  dict(id="OB-004",severity="MEDIUM",language="general",title="String splitting to hide function names",
    pattern=r"['\"][a-zA-Z]{1,5}['\"]\s*\+\s*['\"][a-zA-Z]{1,5}['\"]\s*\+\s*['\"][a-zA-Z]{1,5}['\"]",
    applies_to=None,
    explanation="Splits function/command names to defeat text-based pattern matching.",
    fix="Reconstruct the string and check if it forms a dangerous call."),
  dict(id="OB-005",severity="HIGH",language="general",title="PowerShell encoded command in any file",
    pattern=r"(?i)-En(coded)?C(ommand)?\s+[A-Za-z0-9+/=]{30,}",
    applies_to=None,
    explanation="Hides PS command in a Base64 blob — common in dropper scripts.",
    fix="Decode and audit."),

  # ── CROSS-CUTTING: Exfiltration ───────────────────
  dict(id="EX-001",severity="HIGH",language="general",title="DNS exfiltration pattern",
    pattern=r"(nslookup|dig|host|curl)\s+[^;&#\n]*\$\(.*\)\.[a-z]{2,}\b",
    applies_to=None,
    explanation="Encodes data into DNS query hostname — covert exfiltration channel.",
    fix="Remove DNS-based data transmission."),
  dict(id="EX-002",severity="HIGH",language="general",title="Reading /etc/passwd or shadow",
    pattern=r"(cat|read|open|Get-Content)\s+\/etc\/(passwd|shadow|sudoers)",
    applies_to=None,
    explanation="Reads system user/password database.",
    fix="Remove system file access."),
  dict(id="EX-003",severity="HIGH",language="general",title="Browser cookie / localStorage theft",
    pattern=r"(document\.cookie|localStorage\.getItem|sessionStorage\.getItem).*fetch|XMLHttpRequest",
    applies_to=None,
    explanation="Reads browser cookies/storage and sends them externally — session hijacking.",
    fix="Remove cookie/storage access combined with outbound network calls."),
  dict(id="EX-004",severity="HIGH",language="general",title="Cloud metadata API access",
    pattern=r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2",
    applies_to=None,
    explanation="Accesses cloud instance metadata API — can retrieve IAM tokens and instance credentials.",
    fix="Remove cloud metadata API access. Skills should not query instance metadata."),
  dict(id="EX-005",severity="HIGH",language="general",title="Reverse shell pattern (nc/netcat)",
    pattern=r"\b(nc|ncat|netcat)\s+(-[elnvp ]*)*\d{1,5}\s+(-e\s+|/bin/(ba)?sh)",
    applies_to=None,
    explanation="Creates a reverse shell — gives attacker interactive access to the system.",
    fix="Remove netcat reverse shell commands entirely."),
  dict(id="EX-006",severity="HIGH",language="general",title="Python reverse shell one-liner",
    pattern=r"import\s+socket.*subprocess|socket\.connect\([^)]+\).*os\.dup2",
    applies_to=None,
    explanation="Classic Python reverse shell — connects back to attacker for interactive access.",
    fix="Remove reverse shell code entirely."),
  dict(id="EX-007",severity="MEDIUM",language="general",title="ZIP/TAR of home directory",
    pattern=r"(zip|tar)\s+[^;\n]*(~|\$HOME)\b",
    applies_to=None,
    explanation="Archives the user home directory — common pre-exfiltration step.",
    fix="Remove archiving of home directory. Scope operations to skill's own files."),
]

# ─────────────────────────────────────────
# Base64 deep-decode scanner
# ─────────────────────────────────────────

B64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]")
DANGER_RE = re.compile(r"(curl|wget|bash|sh\s|nc\s|rm\s+-rf|chmod|sudo|/etc/passwd|\.ssh/id_)",re.I)

def check_embedded_base64(content, filepath, report, counter):
    for m in B64_RE.finditer(content):
        try:
            decoded = base64.b64decode(m.group(1)+"==").decode('utf-8',errors='ignore')
            if DANGER_RE.search(decoded):
                counter[0]+=1
                report.findings.append(Finding(
                    id=f"FINDING-{counter[0]:03d}",severity="HIGH",
                    title="[OB-BASE64] Dangerous command hidden in Base64",
                    file=filepath,line=content[:m.start()].count('\n')+1,
                    snippet=f"encoded={m.group(1)[:40]}… → {decoded[:80]}",
                    explanation=f"Base64 decodes to dangerous command: `{decoded[:100]}`",
                    fix="Remove or replace with a documented plaintext command.",language="general"))
        except Exception:
            pass

# ─────────────────────────────────────────
# Zip-slip checker
# ─────────────────────────────────────────

def check_zip_slip(zip_path, report):
    n = len(report.findings)
    try:
        with zipfile.ZipFile(zip_path,'r') as zf:
            for name in zf.namelist():
                if '..' in name or name.startswith('/') or name.startswith('\\'):
                    n+=1
                    report.findings.append(Finding(
                        id=f"FINDING-{n:03d}",severity="HIGH",
                        title="[ZS-001] Zip-slip path traversal in .skill archive",
                        file=f"[archive]/{name}",line=None,snippet=name,
                        explanation="Zip entry with '..' or absolute path writes files outside install dir.",
                        fix="Ensure all archive entries use relative paths without '..' components.",
                        language="general"))
    except Exception:
        pass

# ─────────────────────────────────────────
# Core scan
# ─────────────────────────────────────────

def scan_content(content, filepath, file_lang, report, counter):
    lines = content.splitlines()
    seen: Set[tuple] = set()
    for pd in PATTERNS:
        applies = pd.get("applies_to")
        if applies is not None and file_lang not in applies:
            continue
        cre = re.compile(pd["pattern"], re.IGNORECASE|re.MULTILINE)
        for i,line in enumerate(lines,1):
            if cre.search(line):
                key=(pd["id"],i)
                if key in seen: continue
                seen.add(key)
                counter[0]+=1
                report.findings.append(Finding(
                    id=f"FINDING-{counter[0]:03d}",severity=pd["severity"],
                    title=f"[{pd['id']}] {pd['title']}",
                    file=filepath,line=i,snippet=line.strip()[:120],
                    explanation=pd["explanation"],fix=pd["fix"],
                    language=pd.get("language","general")))
    check_embedded_base64(content, filepath, report, counter)

SCAN_EXT = set(EXT_TO_LANG.keys()) | {'.txt','.env','.envrc'}
IGNORE_EXT = {'.ttf','.otf','.woff','.woff2','.png','.jpg','.gif','.svg',
              '.ico','.pdf','.gz','.zip','.pyc','.class','.jar','.war'}

def audit_directory(skill_dir: Path, original_zip=None) -> AuditReport:
    report = AuditReport(skill_name=skill_dir.name, files_scanned=[])
    if original_zip:
        check_zip_slip(original_zip, report)
    counter = [len(report.findings)]
    for fpath in sorted(skill_dir.rglob('*')):
        if not fpath.is_file(): continue
        name_lower = fpath.name.lower()
        suffix = fpath.suffix.lower()
        if not (name_lower in SPECIAL_FILENAMES or suffix in SCAN_EXT):
            if suffix not in IGNORE_EXT:
                report.skipped_binary.append(str(fpath.relative_to(skill_dir)))
            continue
        rel = str(fpath.relative_to(skill_dir))
        report.files_scanned.append(rel)
        try:
            content = fpath.read_text(errors='replace')
            scan_content(content, rel, detect_language(fpath), report, counter)
        except Exception as e:
            print(f"Warning: could not read {rel}: {e}", file=sys.stderr)
    return report

# ─────────────────────────────────────────
# Report formatting
# ─────────────────────────────────────────

LANG_LABELS = {
    'shell':'🐚 Shell/Bash','python':'🐍 Python','javascript':'🟨 JavaScript',
    'typescript':'🔷 TypeScript','ruby':'💎 Ruby','php':'🐘 PHP','go':'🐹 Go',
    'rust':'🦀 Rust','powershell':'💙 PowerShell','java':'☕ Java','kotlin':'🟣 Kotlin',
    'swift':'🍎 Swift','lua':'🌙 Lua','r':'📊 R','sql':'🗄️ SQL',
    'dockerfile':'🐳 Dockerfile','dotenv':'⚙️ .env','markdown':'📝 Markdown',
    'requirements':'📦 requirements.txt','packagejson':'📦 package.json',
    'general':'🔍 Cross-cutting',
}

def format_report(report: AuditReport) -> str:
    E={"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}
    VE={"DANGEROUS":"🚨","CAUTION":"⚠️","SAFE":"✅"}
    c=report.counts
    lc={}
    for f in report.findings: lc[f.language]=lc.get(f.language,0)+1

    out=[
        f"## 🔍 Security Audit Report: {report.skill_name}","",
        "### Summary",
        f"- **Files scanned**: {len(report.files_scanned)} ({', '.join(report.files_scanned[:5])}{'…' if len(report.files_scanned)>5 else ''})",
        f"- **Total findings**: {len(report.findings)} (🔴 HIGH: {c['HIGH']} | 🟡 MEDIUM: {c['MEDIUM']} | 🟢 LOW: {c['LOW']})",
        f"- **Overall verdict**: {VE[report.verdict]} {report.verdict}",
    ]
    if lc:
        out.append("- **By language**: "+", ".join(f"{LANG_LABELS.get(l,l)}: {n}" for l,n in sorted(lc.items())))
    if report.skipped_binary:
        out.append(f"- **Unrecognized files (not scanned)**: {', '.join(report.skipped_binary)}")
    out.append("")

    if report.findings:
        for sev in ["HIGH","MEDIUM","LOW"]:
            group=[f for f in report.findings if f.severity==sev]
            if not group: continue
            out+=["---","",f"### {E[sev]} {sev} Findings ({len(group)})",""]
            for f in group:
                out+=[
                    f"#### [{f.id}] — {f.title}",
                    f"- **File**: `{f.file}`"+(f", line {f.line}" if f.line else ""),
                    f"- **Language**: {LANG_LABELS.get(f.language,f.language)}",
                    f"- **Code**: `{f.snippet}`",
                    f"- **Why dangerous**: {f.explanation}",
                    f"- **Fix**: {f.fix}","",
                ]
    else:
        out+=["","### ✅ No findings — skill appears safe.",""]

    out+=["---","","### Recommendation"]
    if report.verdict=="DANGEROUS":
        out+=["🚨 **DO NOT INSTALL** until all HIGH findings are resolved.",
              "Apply each fix suggestion above, then re-run this audit."]
    elif report.verdict=="CAUTION":
        out+=["⚠️ **INSTALL WITH CAUTION** — review MEDIUM findings before proceeding.",
              "Confirm each is intentional and properly scoped."]
    else:
        out+=["✅ **SAFE TO INSTALL** — no significant security issues detected."]
    return "\n".join(out)

# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────

def main():
    if len(sys.argv)<2:
        print("Usage: python audit_skill.py <skill-folder-or-.skill-file>"); sys.exit(1)
    target=Path(sys.argv[1])
    if not target.exists():
        print(f"Error: {target} does not exist"); sys.exit(1)

    original_zip=None
    if target.suffix=='.skill':
        original_zip=target
        tmpdir=tempfile.mkdtemp()
        with zipfile.ZipFile(target,'r') as z: z.extractall(tmpdir)
        skill_dir=Path(tmpdir)
    elif target.is_dir():
        skill_dir=target
    else:
        print("Error: provide a .skill zip file or a skill directory"); sys.exit(1)

    report=audit_directory(skill_dir, original_zip=original_zip)
    print(format_report(report)); print()
    json_path=Path(f"{report.skill_name}-audit.json")
    with open(json_path,'w') as fp: json.dump(asdict(report),fp,indent=2,default=str)
    print(f"📄 JSON report saved to: {json_path}")
    sys.exit(2 if report.verdict=="DANGEROUS" else 1 if report.verdict=="CAUTION" else 0)

if __name__=='__main__':
    main()
