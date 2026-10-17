#!/usr/bin/env python3
# 两阶段 Frida 架构伪装安装器（Windows on ARM 绕过 x64-only 安装程序检测）
#
# 阶段1: 以 hook 方式启动安装程序外层 loader；
#        其 CreateProcessW 创建的 /SL5= 子进程被强制 CREATE_SUSPENDED 挂起并上报。
# 阶段2: 先杀外层（阻止临时目录清理），再杀挂起子进程，
#        用 Frida 直接启动解包出的 Setup —— IsWow64Process2 伪装在此进程内生效。
#
# 用法: python bypass_install.py <安装程序.exe> [安装参数...]
# 依赖: pip install frida-tools
import ctypes
import os
import shutil
import sys
import tempfile
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK_JS = os.path.join(HERE, "hook_arch.js")


def die(msg, code=1):
    print("[!] " + msg)
    sys.exit(code)


if len(sys.argv) < 2:
    die('用法: python bypass_install.py <安装程序.exe> [安装参数...]\n'
        '     例: python bypass_install.py "setup-x64.exe" '
        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="%TEMP%\\setup_bypass.log"')

EXE = os.path.abspath(sys.argv[1])
if not os.path.isfile(EXE):
    die("安装程序不存在: " + EXE)
args = sys.argv[2:]

with open(HOOK_JS, encoding="utf-8") as f:
    source = f.read()
parent_source = source.replace("var PARENT_MODE = false;", "var PARENT_MODE = true;")
if parent_source == source:
    die("hook_arch.js 缺少 PARENT_MODE 开关，脚本版本不匹配")

device = frida.get_local_device()


def parse_cmdline(cmd):
    """Windows 命令行 -> argv 列表"""
    argc = ctypes.c_int()
    fun = ctypes.windll.shell32.CommandLineToArgvW
    fun.restype = ctypes.POINTER(ctypes.c_wchar_p)
    ptr = fun(cmd, ctypes.byref(argc))
    if not ptr:
        raise RuntimeError("CommandLineToArgvW failed: " + cmd)
    try:
        return [ptr[i] for i in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(ptr)


def spawn_hooked(argv, script_source):
    """以 Frida hook 方式启动进程并等待其退出，返回 (pid, session, state)"""
    pid = device.spawn(argv)
    session = device.attach(pid)
    state = {"msgs": []}

    def on_message(message, data):
        print("[frida]", message)
        if message.get("type") == "send":
            state["msgs"].append(message.get("payload"))

    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    print("[*] spawned pid=%d argv0=%s" % (pid, argv[0]))
    return pid, session, state


# ---------- 阶段1: 外层 loader ----------
pid1, session1, state1 = spawn_hooked([EXE] + args, parent_source)
while not state1["msgs"] and session1.is_detached is False:
    time.sleep(0.05)

if not state1["msgs"]:
    # 外层未产生 /SL5= 子进程就退出：可能该安装程序自身完成安装（hook 已生效），
    # 也可能不适用本技能 —— 判定依据是安装日志中的 "Windows architecture" 行。
    print("[*] 外层未产生子进程即退出。请检查安装日志:")
    print("    若为 Windows architecture: x64 (64-bit) 则伪装已生效，安装完成;")
    print("    若仍为 Arm64 或无日志，则该安装程序不适用本技能（非 Inno SetupLdr）。")
    sys.exit(0)

sl5 = [m for m in state1["msgs"] if m.get("cmdline") and "/SL5=" in m["cmdline"]]
child = sl5[0] if sl5 else state1["msgs"][0]
print("[*] 捕获挂起子进程: pid=%s cmdline=%s" % (child["pid"], child.get("cmdline")))

argv2 = parse_cmdline(child["cmdline"])
print("[*] 阶段2 argv: %r" % (argv2,))

# 先杀外层（阻止其清理临时目录），再杀挂起子进程
try:
    device.kill(pid1)
    print("[*] 外层已终止")
except Exception as e:
    print("[-] kill 外层失败: %s" % e)
try:
    device.kill(child["pid"])
    print("[*] 挂起子进程已终止")
except Exception as e:
    print("[-] kill 子进程失败: %s" % e)

# ---------- 阶段2: 直接启动解包出的 Setup（架构伪装） ----------
pid2, session2, state2 = spawn_hooked(argv2, source)
try:
    while session2.is_detached is False:
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
print("[*] Setup 进程已退出")

# 清理外层 loader 留下的解包目录（外层被强杀，不会自清）
leftover = os.path.dirname(argv2[0])
if leftover.lower().startswith(tempfile.gettempdir().lower()):
    shutil.rmtree(leftover, ignore_errors=True)
    print("[*] 已清理外层解包目录: " + leftover)

print("[*] 全部完成。请在安装日志中核验: Windows architecture: x64 (64-bit)")
