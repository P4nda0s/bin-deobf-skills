# Binary Deobfuscation Skills

English | [中文](README.md)

Binary deobfuscation analysis skills, supporting 40+ AI coding tools. **AArch64 only.**

> Recommended course: [Obfuscation & Deobfuscation](https://bin-lab.cn/courses/obfuscation-deobfuscation) — learn the fundamentals for better results

Designed for **IDA-NO-MCP** — export decompiled results from IDA, then analyze and deobfuscate with AI coding tools.

## Included Skills

| Skill | Description |
|-------|-------------|
| deobf-cff | Recover original control flow from flattened (CFF/OLLVM-style) functions |
| deobf-indirect | Resolve indirect branches and calls to their real targets |
| deobf-bcf | Identify and remove bogus control flow and opaque predicates |
| deobf-string | Decrypt and recover obfuscated strings |

## Usage Example

```
deobf-indirect 反混淆 xxx.elf 的 0x45614 函数
```

## Installation

```bash
npx skills add P4nda0s/bin-deobf-skills
```

## Update & Uninstall

```bash
# Check for updates
npx skills check

# Update
npx skills update https://github.com/P4nda0s/bin-deobf-skills

# Uninstall
npx skills remove bin-deobf-skills
```

## WeChat

<img src="images/wechat_qrcode.jpg" width="300" alt="WeChat QR Code">
