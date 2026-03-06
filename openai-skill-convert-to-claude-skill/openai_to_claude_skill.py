#!/usr/bin/env python3
"""
openai_to_claude_skill.py
=========================
将 openai/skills 仓库中的 Codex Skill 批量转换为 Claude Code 兼容格式。

用法:
  # 转换整个 openai/skills 仓库
  python openai_to_claude_skill.py --repo https://github.com/openai/skills --output ./claude-skills

  # 转换本地已有的 openai skill 目录
  python openai_to_claude_skill.py --local ./my-openai-skills --output ./claude-skills

  # 只转换单个 skill 目录
  python openai_to_claude_skill.py --skill ./my-openai-skills/gh-address-comments --output ./claude-skills

  # 转换后直接安装到 Claude Code 用户目录
  python openai_to_claude_skill.py --repo https://github.com/openai/skills --install

依赖: pip install pyyaml requests
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("❌ 请先安装依赖: pip install pyyaml requests")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("❌ 请先安装依赖: pip install pyyaml requests")
    sys.exit(1)


# ─────────────────────────────────────────────
# 颜色输出
# ─────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    GREEN = "\033[92m"
    CYAN  = "\033[96m"
    YELLOW= "\033[93m"
    RED   = "\033[91m"
    DIM   = "\033[2m"

def ok(msg):   print(f"{C.GREEN}✔{C.RESET}  {msg}")
def info(msg): print(f"{C.CYAN}ℹ{C.RESET}  {msg}")
def warn(msg): print(f"{C.YELLOW}⚠{C.RESET}  {msg}")
def err(msg):  print(f"{C.RED}✘{C.RESET}  {msg}")
def head(msg): print(f"\n{C.BOLD}{C.CYAN}{msg}{C.RESET}")


# ─────────────────────────────────────────────
# SKILL.md 解析
# ─────────────────────────────────────────────

def parse_skill_md(path: Path) -> dict:
    """解析 SKILL.md，返回 {frontmatter: dict, body: str, raw: str}"""
    raw = path.read_text(encoding="utf-8")

    frontmatter = {}
    body = raw

    # 提取 YAML frontmatter（--- ... ---）
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)", raw, re.DOTALL)
    if fm_match:
        try:
            frontmatter = yaml.safe_load(fm_match.group(1)) or {}
        except yaml.YAMLError as e:
            warn(f"  YAML 解析警告: {e}")
        body = fm_match.group(2).lstrip("\n")
    else:
        warn(f"  {path} 无 YAML frontmatter，将作为纯 body 处理")

    return {"frontmatter": frontmatter, "body": body, "raw": raw}


def parse_openai_yaml(skill_dir: Path) -> dict:
    """解析 agents/openai.yaml，提取 UI 元数据和策略"""
    yaml_path = skill_dir / "agents" / "openai.yaml"
    if not yaml_path.exists():
        return {}
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        return data
    except yaml.YAMLError:
        warn(f"  无法解析 {yaml_path}")
        return {}


# ─────────────────────────────────────────────
# description 改写（Codex 边界风格 → Claude 推动风格）
# ─────────────────────────────────────────────

def rewrite_description(description: str, skill_name: str) -> str:
    """
    将 Codex 风格的 description（描述边界/限制）
    改写为 Claude Code 风格（推动触发，列举场景关键词）。
    保留原意，追加触发指引。
    """
    if not description:
        return f"Use this skill for {skill_name} tasks."

    desc = description.strip()

    # 如果描述已经包含"Use when"或"Use this skill"风格，直接追加 Claude 触发语
    trigger_hint = (
        " Use this skill proactively whenever the user's request relates to "
        "this domain, even if they don't explicitly name the skill."
    )

    # 避免重复追加
    if "proactively" not in desc and "even if they don't" not in desc:
        desc = desc.rstrip(".") + "." + trigger_hint

    return desc


# ─────────────────────────────────────────────
# 构建 Claude SKILL.md 内容
# ─────────────────────────────────────────────

def build_claude_frontmatter(
    openai_fm: dict,
    openai_yaml: dict,
    skill_name: str,
) -> dict:
    """
    将 OpenAI frontmatter + agents/openai.yaml 合并为 Claude frontmatter。

    OpenAI frontmatter 字段:
      name, description（仅这两个）

    agents/openai.yaml 字段:
      interface.display_name, interface.short_description
      policy.allow_implicit_invocation
      dependencies.tools（MCP 列表）

    Claude frontmatter 支持字段:
      name, description, version（可选）
      disable-model-invocation（可选，对应 allow_implicit_invocation: false）
      compatibility（可选，描述 MCP 依赖）
    """
    claude_fm = {}

    # name: 优先使用 openai frontmatter，否则用目录名
    claude_fm["name"] = openai_fm.get("name") or skill_name

    # description: 改写风格
    raw_desc = openai_fm.get("description", "")
    claude_fm["description"] = rewrite_description(raw_desc, skill_name)

    # version: 如果 OpenAI 有则保留
    if "version" in openai_fm:
        claude_fm["version"] = openai_fm["version"]

    # allow_implicit_invocation: false → disable-model-invocation: true
    policy = openai_yaml.get("policy", {})
    allow_implicit = policy.get("allow_implicit_invocation", True)
    if allow_implicit is False:
        claude_fm["disable-model-invocation"] = True

    # MCP 依赖 → compatibility 注释
    deps = openai_yaml.get("dependencies", {})
    tools = deps.get("tools", [])
    if tools:
        mcp_names = []
        for t in tools:
            if isinstance(t, dict):
                val = t.get("value") or t.get("name", "")
                desc_t = t.get("description", "")
                url_t  = t.get("url", "")
                parts = [val]
                if desc_t: parts.append(desc_t)
                if url_t:  parts.append(f"({url_t})")
                mcp_names.append(" ".join(parts))
        if mcp_names:
            claude_fm["compatibility"] = "Requires MCP tools: " + "; ".join(mcp_names)

    return claude_fm


def render_frontmatter(fm: dict) -> str:
    """将 dict 渲染为 YAML frontmatter 字符串"""
    lines = ["---"]
    for k, v in fm.items():
        if isinstance(v, str) and ("\n" in v or len(v) > 80):
            # 多行字符串用 | 块样式
            lines.append(f"{k}: |")
            for line in v.splitlines():
                lines.append(f"  {line}")
        elif isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        else:
            # 对含特殊字符的字符串加引号
            safe = str(v)
            if any(c in safe for c in [':', '#', '@', '`', '"', "'"]):
                safe = json.dumps(safe)  # JSON 双引号包裹
            lines.append(f"{k}: {safe}")
    lines.append("---")
    return "\n".join(lines)


def build_claude_skill_md(
    openai_fm: dict,
    openai_yaml: dict,
    body: str,
    skill_name: str,
    source_tier: str,  # system / curated / experimental / local
) -> str:
    """组装完整的 Claude SKILL.md 内容"""
    claude_fm = build_claude_frontmatter(openai_fm, openai_yaml, skill_name)
    fm_str = render_frontmatter(claude_fm)

    # 添加转换注释头
    interface = openai_yaml.get("interface", {})
    display_name    = interface.get("display_name", "")
    short_desc      = interface.get("short_description", "")
    default_prompt  = interface.get("default_prompt", "")

    meta_lines = [
        f"<!-- Converted from OpenAI Codex skill [{skill_name}] (tier: {source_tier}) -->",
    ]
    if display_name:
        meta_lines.append(f"<!-- OpenAI display_name: {display_name} -->")
    if short_desc:
        meta_lines.append(f"<!-- OpenAI short_description: {short_desc} -->")
    if default_prompt:
        meta_lines.append(f"<!-- OpenAI default_prompt: {default_prompt} -->")
    meta_comment = "\n".join(meta_lines)

    # 清理 body 中 OpenAI 专属引用（可选）
    cleaned_body = clean_body(body)

    return f"{fm_str}\n\n{meta_comment}\n\n{cleaned_body}"


def clean_body(body: str) -> str:
    """
    清理 body 中 OpenAI/Codex 专属的引用：
    - $skill-installer → /skill-name
    - $<skill-name>    → /<skill-name>
    - ~/.codex/        → ~/.claude/
    - .agents/skills/  → .claude/skills/
    - Codex            → Claude Code（仅在上下文合适时）
    """
    text = body
    # 路径替换
    text = text.replace("~/.codex/skills/", "~/.claude/skills/")
    text = text.replace("~/.agents/skills/", "~/.claude/skills/")
    text = text.replace(".agents/skills/",   ".claude/skills/")
    text = text.replace("$CODEX_HOME/skills", "~/.claude/skills")
    # $ 前缀 skill 调用 → / 前缀
    text = re.sub(r'\$skill-installer\b', '/skill-installer', text)
    text = re.sub(r'\$([a-z][a-z0-9-]+)\b', r'/\1', text)
    return text


# ─────────────────────────────────────────────
# 转换单个 skill 目录
# ─────────────────────────────────────────────

def convert_skill(
    skill_dir: Path,
    output_dir: Path,
    source_tier: str = "unknown",
) -> bool:
    """
    转换一个 OpenAI skill 目录 → Claude skill 目录。
    返回 True 表示成功。
    """
    skill_md_path = skill_dir / "SKILL.md"
    if not skill_md_path.exists():
        warn(f"  跳过 {skill_dir.name}：未找到 SKILL.md")
        return False

    skill_name = skill_dir.name.lstrip(".")  # 去掉 .system 等前缀点

    # 解析输入
    parsed   = parse_skill_md(skill_md_path)
    oai_yaml = parse_openai_yaml(skill_dir)

    # 构建输出目录
    out_skill_dir = output_dir / skill_name
    out_skill_dir.mkdir(parents=True, exist_ok=True)

    # 写入新 SKILL.md
    new_skill_md = build_claude_skill_md(
        openai_fm   = parsed["frontmatter"],
        openai_yaml = oai_yaml,
        body        = parsed["body"],
        skill_name  = skill_name,
        source_tier = source_tier,
    )
    (out_skill_dir / "SKILL.md").write_text(new_skill_md, encoding="utf-8")

    # 复制其他文件（排除 agents/openai.yaml，这是 Codex 专属）
    for item in skill_dir.iterdir():
        if item.name == "SKILL.md":
            continue  # 已处理

        if item.is_dir() and item.name == "agents":
            # agents 目录：跳过 openai.yaml，保留其他文件（如果有）
            oai_yaml_file = item / "openai.yaml"
            for sub in item.iterdir():
                if sub == oai_yaml_file:
                    continue  # 跳过 openai.yaml
                dest = out_skill_dir / "agents" / sub.name
                dest.parent.mkdir(exist_ok=True)
                if sub.is_file():
                    shutil.copy2(sub, dest)
            continue

        # 其他目录/文件直接复制
        dest = out_skill_dir / item.name
        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    return True


# ─────────────────────────────────────────────
# 下载 openai/skills 仓库
# ─────────────────────────────────────────────

GITHUB_API = "https://api.github.com"

def download_github_repo(repo_url: str, dest: Path) -> Path:
    """
    下载 GitHub 仓库 ZIP 并解压。
    repo_url 示例: https://github.com/openai/skills
    """
    # 解析 owner/repo
    m = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
    if not m:
        raise ValueError(f"无法解析 GitHub URL: {repo_url}")
    owner, repo = m.group(1), m.group(2).rstrip("/")

    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
    info(f"下载仓库 {owner}/{repo} ...")
    info(f"URL: {zip_url}")

    resp = requests.get(zip_url, stream=True, timeout=60)
    resp.raise_for_status()

    zip_path = dest / "repo.zip"
    with open(zip_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

    info("解压中...")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)

    # 找到解压后的根目录（通常是 <repo>-main/）
    extracted_dirs = [d for d in dest.iterdir() if d.is_dir() and d.name != "__MACOSX"]
    if not extracted_dirs:
        raise RuntimeError("解压后未找到目录")

    repo_root = extracted_dirs[0]
    zip_path.unlink()
    ok(f"仓库已下载到: {repo_root}")
    return repo_root


def find_skill_dirs(root: Path) -> list[tuple[Path, str]]:
    """
    在仓库根目录中找到所有 skill 目录。
    返回 [(skill_dir, tier), ...]
    """
    results = []
    skills_root = root / "skills"
    if not skills_root.exists():
        # 如果没有 skills/ 子目录，把根目录当作 skill 集合
        skills_root = root

    # 遍历三个 tier 目录
    tier_map = {
        ".system":      "system",
        ".curated":     "curated",
        ".experimental":"experimental",
    }

    for tier_dir_name, tier_label in tier_map.items():
        tier_path = skills_root / tier_dir_name
        if tier_path.exists():
            for skill_dir in sorted(tier_path.iterdir()):
                if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
                    results.append((skill_dir, tier_label))

    # 处理直接在 skills/ 下的 skill（没有 tier 子目录）
    for item in sorted(skills_root.iterdir()):
        if item.is_dir() and not item.name.startswith(".") and (item / "SKILL.md").exists():
            results.append((item, "local"))

    return results


# ─────────────────────────────────────────────
# Claude Code 安装路径
# ─────────────────────────────────────────────

def get_claude_skills_dir() -> Path:
    return Path.home() / ".claude" / "skills"


# ─────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────

def run_conversion(
    skill_dirs: list[tuple[Path, str]],
    output_dir: Path,
    install: bool = False,
) -> dict:
    """批量转换并统计结果"""
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = {"success": 0, "skipped": 0, "failed": 0}

    head(f"开始转换 {len(skill_dirs)} 个 skill ...")

    for skill_dir, tier in skill_dirs:
        label = f"[{tier}] {skill_dir.name}"
        try:
            converted = convert_skill(skill_dir, output_dir, tier)
            if converted:
                ok(label)
                stats["success"] += 1
            else:
                stats["skipped"] += 1
        except Exception as e:
            err(f"{label}: {e}")
            stats["failed"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="将 OpenAI Codex Skills 转换为 Claude Code Skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--repo", metavar="URL",
        help="GitHub 仓库 URL（如 https://github.com/openai/skills）",
    )
    source_group.add_argument(
        "--local", metavar="DIR",
        help="本地 openai skills 根目录",
    )
    source_group.add_argument(
        "--skill", metavar="DIR",
        help="单个 skill 目录（含 SKILL.md）",
    )

    parser.add_argument(
        "--output", "-o", metavar="DIR",
        default="./claude-skills",
        help="输出目录（默认: ./claude-skills）",
    )
    parser.add_argument(
        "--install", action="store_true",
        help="转换后自动安装到 ~/.claude/skills/",
    )
    parser.add_argument(
        "--tier", choices=["system", "curated", "experimental", "all"],
        default="all",
        help="只转换指定 tier（默认: all）",
    )

    args = parser.parse_args()
    output_dir = Path(args.output).resolve()

    # ── 确定来源 ──
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        if args.repo:
            repo_root = download_github_repo(args.repo, tmp_path)
            skill_dirs = find_skill_dirs(repo_root)

        elif args.local:
            local_root = Path(args.local).resolve()
            if not local_root.exists():
                err(f"目录不存在: {local_root}")
                sys.exit(1)
            skill_dirs = find_skill_dirs(local_root)

        else:  # --skill
            skill_path = Path(args.skill).resolve()
            if not skill_path.exists():
                err(f"目录不存在: {skill_path}")
                sys.exit(1)
            skill_dirs = [(skill_path, "local")]

        # ── Tier 过滤 ──
        if args.tier != "all":
            skill_dirs = [(d, t) for d, t in skill_dirs if t == args.tier]

        if not skill_dirs:
            warn("没有找到任何 skill，请检查来源路径。")
            sys.exit(0)

        info(f"找到 {len(skill_dirs)} 个 skill")
        for d, t in skill_dirs:
            print(f"  {C.DIM}[{t}]{C.RESET} {d.name}")

        # ── 执行转换 ──
        stats = run_conversion(skill_dirs, output_dir)

        # ── 安装到 Claude Code ──
        if args.install or input("\n是否安装到 ~/.claude/skills/？[y/N] ").strip().lower() == "y":
            claude_dir = get_claude_skills_dir()
            claude_dir.mkdir(parents=True, exist_ok=True)
            installed = 0
            for item in output_dir.iterdir():
                if item.is_dir():
                    dest = claude_dir / item.name
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                    installed += 1
            ok(f"已安装 {installed} 个 skill 到 {claude_dir}")
            info("重启 Claude Code 后即可使用（运行 /skills 查看列表）")

    # ── 报告 ──
    head("转换完成")
    print(f"  {C.GREEN}成功{C.RESET}: {stats['success']}")
    print(f"  {C.YELLOW}跳过{C.RESET}: {stats['skipped']}")
    print(f"  {C.RED}失败{C.RESET}: {stats['failed']}")
    print(f"  输出目录: {output_dir}")

    if stats["success"] > 0:
        print(f"\n{C.BOLD}使用方式:{C.RESET}")
        print(f"  1. 将 {output_dir} 中的目录复制到 ~/.claude/skills/")
        print(f"  2. 或重新运行并加 --install 参数自动安装")
        print(f"  3. 在 Claude Code 中运行 /skills 查看已安装的 skill")


if __name__ == "__main__":
    main()
