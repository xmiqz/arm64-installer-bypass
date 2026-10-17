# arm64-installer-bypass

在 **Windows on ARM (arm64)** 设备上安装 x64-only 安装程序（典型：Inno Setup 打包、`ArchitecturesAllowed=x64`）的技能。用 Frida 注入安装进程，hook `IsWow64Process2` 伪装 `NativeMachine=0x8664 (AMD64)`，让安装程序误判设备为 x64，通过架构检查完成安装。

解决的典型报错：**"这个程序不支持该版本的计算机运行"** / `A processor architecture mismatch` —— 安装日志特征为 `Windows architecture: Arm64 (64-bit)` 后 `Got EAbort exception`。

## 工作原理

Inno Setup 6.4 的架构检测优先调用 `IsWow64Process2`，拿到真实 `NativeMachine=0xAA64` 即中止。难点在于**外层 SetupLdr 会把真正的 Setup 解包到 `%TEMP%\is-*.tmp\` 并以 `/SL5=` 参数另起子进程**——架构检查发生在子进程里，而 Frida 的 spawn gating 在 Windows 不可用。因此采用两阶段交接：

1. **阶段 1**：hook 外层 `CreateProcessW`，检测到命令行含 `/SL5=` 时强制加 `CREATE_SUSPENDED` 挂起子进程并上报（其余子进程创建放行，不误伤安装过程）。
2. **阶段 2**：先杀外层（阻止其清理临时目录），再杀挂起子进程，用 Frida 直接启动解包出的 Setup——架构 hook 在正确的进程里生效。

## 使用

```
pip install frida-tools
python scripts/bypass_install.py "<安装程序.exe>" [安装参数...]
```

静默安装示例：

```
python scripts/bypass_install.py "setup-x64.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="%TEMP%\setup_bypass.log"
```

安装日志出现以下行即成功：

```
Windows architecture: x64 (64-bit)
64-bit install mode: Yes
```

## 适用边界

- **适用**：Windows 11 on ARM（x64 Prism 模拟可用）上的 Inno Setup 6.x 安装程序。
- **不适用**：ARM64 原生安装包；NSIS/MSI 等其他打包器（两阶段交接依赖 Inno SetupLdr 的 `/SL5=` 重执行机制）；许可/授权/DRM 类检查绕过——本项目仅解决操作系统架构兼容性问题。
- **前置**：Python 3.10+；目标应用必须先完全退出；非管理员即可。

## 目录

```
SKILL.md                  # 技能正文（用法、检查点、排障表）
scripts/bypass_install.py # 两阶段编排器（CLI 核心）
scripts/hook_arch.js      # Frida 脚本：架构伪装 + /SL5= 挂起拦截
```

## 许可

MIT
