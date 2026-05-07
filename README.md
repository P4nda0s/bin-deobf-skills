# 二进制反混淆技能集

[English](README_en.md) | 中文

二进制反混淆分析技能，支持 40+ 种 AI 编程工具。**仅支持 AArch64 架构。**

> 推荐配套课程：[混淆与反混淆](https://bin-lab.cn/courses/obfuscation-deobfuscation) — 学习原理，更好掌握

## 包含的技能

| 技能 | 描述 | 开发 | 测试 |
|------|------|:----:|:----:|
| deobf-cff | 从平坦化（CFF/OLLVM 风格）函数中恢复原始控制流 | | |
| deobf-indirect | 解析间接跳转和间接调用的真实目标 | ✅ | ✅ |
| deobf-bcf | 识别并移除虚假控制流和不透明谓词 | | |
| deobf-string | 解密和恢复被混淆的字符串 | ✅ | ✅ |

## 使用示例

```
deobf-indirect 反混淆 tests/goron-indbr-miniz-example2 的 main 函数
```

## 安装

```bash
npx skills add P4nda0s/bin-deobf-skills
```

## 更新与卸载

```bash
# 检查更新
npx skills check

# 更新
npx skills update https://github.com/P4nda0s/bin-deobf-skills

# 卸载
npx skills remove bin-deobf-skills
```

## 关注公众号

<img src="images/wechat_qrcode.jpg" width="300" alt="二进制磨剑 公众号二维码">
