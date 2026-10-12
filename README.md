<div align="center">

# 🔐 go-tp-link-decrypt

**TP-Link 固件解密工具 · Go 重构版**

用 Go 完整重写的 TP-Link 固件解密器，内置密钥、离线运行，
并基于 [bubbletea](https://github.com/charmbracelet/bubbletea) 提供 **TUI 选项卡交互式确认界面**。

> 本项目为 **Web & CLI 重构**，**解密逻辑与算法完全移植自原作者的开源 C 工具**。
>
> 原 C 语言版本作者：**[Watchful_IP](https://watchfulip.github.io) & robbins**
> 遵循 **GPL-3.0** 许可证。本 Go 版同样以 GPL-3.0 发布。

<p>
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/TUI-bubbletea-6F3FE8" alt="bubbletea">
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-2ea44f" alt="Platform">
</p>

</div>

---

## ✨ 特性

| 固件类型 | 解密方式 | 内置密钥 |
|:--------|:--------|:--------|
| **fw-type**（路由器 / AP） | RSA-PSS-SHA256 验签 + AES-128-CBC | `RSA1` |
| **Tapo / IPC**（摄像头） | RSA-PSS-SHA256 验签 + AES-128-CBC | `RSA0` |
| **Switch / Omada**（交换机） | DES-CBC | `DES_KEY` / `DES_IV` |

- 🔑 **密钥内置** — 无需联网、无需运行 `extract_keys.sh`，彻底离线可用
- 🖥️ **TUI 选项卡界面** — Tab/方向键切换，输入路径、确认解密、查看密钥与关于
- ⚡ **CLI 快速模式** — 传参即解密，跳过交互界面
- 🧩 **纯 Go 标准库** — 用 `crypto/rsa`、`crypto/aes`、`crypto/des` 等重写原 C 的自实现算法
- 🖥️ **双平台构建脚本** — 一条命令交叉编译 Windows / Linux

---

## 📦 项目结构

```
go-tp-link-decrypt/
├── main.go                    # 入口：CLI 或 TUI
├── keys/keys.go               # 内置 RSA/DES 密钥（含来源注释）
├── internal/
│   ├── fw/fw.go               # 固件类型检测 + 签名长度判断
│   ├── decrypt/decrypt.go     # RSA 验签 / AES-CBC / DES-CBC 解密
│   └── ui/ui.go               # bubbletea TUI 选项卡菜单
├── build.ps1                  # Windows 交叉编译脚本
├── build.sh                   # Linux/macOS 构建脚本
└── go.mod / go.sum
```

---

## 🚀 快速开始

### 环境要求

- **Go 1.21+**（建议 1.25+）
- 无需 OpenSSL / 网络连接

### 构建

```powershell
# Windows / PowerShell
cd go-tp-link-decrypt
go mod tidy
go build -o tp-link-decrypt.exe .
```

```bash
# Linux / macOS
cd go-tp-link-decrypt
go mod tidy
go build -o tp-link-decrypt .
```

> 💡 也可使用双平台构建脚本，一键产出 Windows + Linux 二进制：
>
> ```powershell
> .\build.ps1        # Windows 上同时构建两个平台
> ```
>
> ```bash
> ./build.sh         # Linux/macOS 上同时构建两个平台
> ```
>
> 产物输出到 `dist/`。

---

## 🕹️ 使用

### 模式一：TUI 交互界面

```powershell
.\tp-link-decrypt.exe
```

进入界面后按步骤操作：

1. **解密固件** 选项卡 → `↑/↓` 选择模式（自动检测 / 强制 fw-type / 强制 Tapo / 强制 Switch）→ `Enter`
2. 输入固件文件路径 → `Enter`
3. 核对解密模式 → `Enter` 开始解密
4. 查看结果 → `Enter` 返回

其他选项卡：

- **密钥信息** — 查看内置的 RSA / DES 密钥
- **关于** — 版本、来源与授权信息

**按键说明**

| 按键 | 作用 |
|:-----|:-----|
| `Tab` / `←` / `→` | 切换选项卡 |
| `↑` / `↓` | 切换模式 |
| `Enter` | 确认 / 下一步 |
| `Esc` | 返回 |
| `q` / `Ctrl+C` | 退出 |

### 模式二：CLI 快速解密

```powershell
.\tp-link-decrypt.exe <firmware_file>
```

解密成功后，在同目录生成 `<firmware_file>.dec`。

---

## 📖 解密原理

TP-Link 固件使用自定义的 RSA-PSS 签名 + AES/DES 加密，本工具精确还原了原 C 逻辑：

- **RSA-PSS 验签** — 手动 RSA 解密 → 校验 `0xbc` 尾标记 → MGF1 掩码 → 双重 SHA256 校验，无需标准 `rsa.VerifyPSS`
- **签名字节序** — 验签前将签名反转（与原 C 工具 `rsaVerifySign` 一致）
- **签名区清零** — 验签前清空签名区，清零后的缓冲区计入验签数据
- **密钥来源** — 从官方固件中的 `RSA_0` / `RSA_1` 及 `DES_KEY` / `DES_IV` 提取，经 SHA256 校验（`0a7857d4...b6e64`）

> **仅支持 RSA-2048**（`RSA_VER==0x200`）固件。RSA-1024（`0x100`）固件会按设计报错并提示 "likely not encrypted"，与原 C 工具行为一致。

---

## 🙏 致谢与署名

本项目的**解密算法、偏移量与密钥提取**完全来自以下开源 C 工具，特此声明并致谢：

> **原版 C 工具作者：Watchful_IP & robbins**
> 项目主页：[watchfulip.github.io](https://watchfulip.github.io)
> 许可证：**GNU General Public License v3.0**

密钥来源固件链接（由原作者提供，仅用于一次性提取密钥，本 Go 版已内置、无需下载）：

- `Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin` → `RSA0`
- `ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_...bin.rollback` → `RSA1`
- `rtk-maple_gpl.tar.gz` → `DES_KEY` / `DES_IV`

---

## 📄 License

本项目基于 **GPL-3.0** 许可证发布，与原始 C 工具保持一致。

<sub>本工具仅供研究 / 恢复自有设备固件使用，请遵守当地法律法规。</sub>
