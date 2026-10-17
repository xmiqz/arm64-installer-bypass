---
name: arm64-installer-bypass
description: 在 Windows on ARM (arm64) 上伪装 x64 绕过安装程序架构检测（Frida hook IsWow64Process2 + Inno Setup 子进程交接）。Use when an installer on ARM64 Windows aborts with 这个程序不支持该版本的计算机运行 or a processor architecture is not supported error. Not for ARM64-native installers.
---

# arm64-installer-bypass

在 Windows on ARM 设备上安装 **x64-only 安装程序**（典型：Inno Setup 打包、
`ArchitecturesAllowed=x64` 精确匹配）的绕过技能。核心手段：用 Frida 注入
安装进程，hook `IsWow64Process2` 使其返回 `NativeMachine=0x8664 (AMD64)`，
让安装程序误判设备为 x64，从而通过架构检查完成安装。

## 1. 适用边界（先判断，再动手）

- **适用**：Inno Setup 6.x 安装程序（64 位 installer）在 ARM64 Windows 上报
  "这个程序不支持该版本的计算机运行"；日志特征
  `Windows architecture: Arm64 (64-bit)` + `Got EAbort exception`。
- **不适用**：
  - ARM64 原生安装包（无需绕过，直接装）。
  - 非 Inno 安装程序（NSIS/MSI 等）——本技能的两阶段交接依赖 Inno SetupLdr
    的 `/SL5=` 重执行机制；其他打包器需先用第 5 节方法确认其检测 API。
  - 绕过许可/授权/DRM 类检查——本技能仅用于解决**操作系统架构兼容性**问题。
- **前置条件**：Windows 11 on ARM（x64 Prism 模拟可用）；Python 3.10+；
  `pip install frida-tools`；**非管理员即可**（安装程序 asInvoker）。
- **红线**：安装的目标应用必须先完全退出（否则安装程序会以"应用正在运行"
  中止，静默模式默认选"取消"）。若目标应用就是当前 IDE 本身，提醒用户
  手动退出后运行，或先做一个桌面 .bat 启动器交由用户操作，**不要强杀宿主**。

## 2. 原理（为什么必须两阶段）

1. Inno Setup 6.4 架构检测优先调用 `IsWow64Process2`，拿到真实
   `NativeMachine=0xAA64 (ARM64)` → `paArm64`；`ArchitecturesAllowed=x64`
   是**精确匹配** → 失败 → `msgWindowsVersionNotSupported` 中止。
   （模拟层下 `GetNativeSystemInfo` 反而返回 AMD64，所以只要让
   `IsWow64Process2` 调用失败或返回 0x8664 即可骗过。）
2. **外层 loader 会另起子进程**：Inno SetupLdr 把真正的 Setup 解包到
   `%TEMP%\is-*.tmp\` 并以 `/SL5="<hwnd>,<offset0>,<offset1>,<原文件>"` 参数
   重新执行——架构检查发生在**子进程**里。Frida 的 spawn gating 在 Windows
   不支持，外层 hook 打不到子进程，因此必须两阶段交接：
   - **阶段 1**：hook 外层 `CreateProcessW`，检测到命令行含 `/SL5=` 时强制
     加 `CREATE_SUSPENDED` 挂起子进程并上报（不带 `/SL5=` 的创建放行，
     避免误伤安装过程中的其他子进程）。
   - **阶段 2**：先杀外层（阻止其清理临时目录），再杀挂起子进程，
     用 Frida 直接启动解包出的 Setup——此时架构 hook 在正确的进程里生效。

## 3. 标准用法

```
pip install frida-tools
python scripts/bypass_install.py "<安装程序.exe>" [安装参数...]
```

推荐参数（静默安装）：

```
python scripts/bypass_install.py "setup-x64.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="%TEMP%\setup_bypass.log"
```

不传参数则以原始 GUI 向导模式启动（同样经过架构伪装）。

**安装前后核验**（安装日志必须出现以下行才算成功）：

```
Windows architecture: x64 (64-bit)
64-bit install mode: Yes
```

若日志仍为 `Arm64`，说明 hook 没落在真正做检测的进程上（见第 5 节）。

## 4. 执行前检查点

1. `pip show frida` 确认已安装（frida 17.x 自带 Windows ARM64 轮子）。
2. 目标应用**已完全退出**（任务管理器里无残留进程，含托盘）。
3. 安装参数里带 `/LOG=`，方便事后判定架构伪装是否生效。
4. 安装程序路径含空格/中文无碍（脚本按 argv 数组传递，不拼接命令行）。
5. 若本机杀软对进程注入报警：Frida 注入是本技能的必要行为，需用户放行
   或改在可信环境执行；不要静默绕过杀软。

## 5. 排障

| 现象 | 原因与处置 |
|------|-----------|
| 阶段 1 输出"未捕获子进程，外层已退出" | 该安装程序没有 SetupLdr 重执行（非 Inno 或已处于 `/SL5` 模式）。若它自身完成安装且日志显示 x64，则伪装已在其内部生效，属正常完成；否则该安装器不适用本技能。 |
| 阶段 2 日志仍为 `Arm64` | hook 未命中：确认 `setup_*.log` 与执行器输出是否同一次运行；用第 3 节带 `/LOG=` 重跑并比对时间戳。 |
| 报错"应用当前正在运行" | 目标应用未退净。完成安装前不得启动目标应用。 |
| `frida.NotSupportedError: not yet supported on this OS` | spawn gating 在 Windows 不可用——本技能因此采用两阶段交接，不要回退到 gating 方案。 |
| 子进程被挂起后无后续 | 检查执行器是否被终止（中断执行器会留下 `%TEMP%\is-*.tmp`，手动删除即可，无副作用）。 |
| 需要取证 hook 是否命中 | `scripts/hook_arch.js` 内去掉 spoof 逻辑改用 `Interceptor.attach` 打印 caller 即可（源码注释有说明）。 |

## 6. 目录

- `scripts/bypass_install.py` — 两阶段编排器（CLI 核心）。
- `scripts/hook_arch.js` — Frida 脚本：`IsWow64Process2` 伪装 + 外层
  `CreateProcessW` 挂起拦截（`PARENT_MODE` 开关区分两个阶段）。
