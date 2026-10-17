// arm64-installer-bypass Frida 脚本
//
// 主功能（两阶段通用）：拦截 IsWow64Process2，调用返回后把 NativeMachine
// 改写为 0x8664 (AMD64)，使 Inno Setup 判定 ProcessorArchitecture = paX64，
// 通过 ArchitecturesAllowed=x64 的精确匹配检查。
//
// PARENT_MODE = true（外层 loader 进程专用）：拦截 CreateProcessW，仅当
// 命令行含 /SL5=（Inno SetupLdr 重执行子进程）时强制 CREATE_SUSPENDED
// 挂起并上报 Python 编排；其余子进程创建原样放行，不误伤安装过程。
//
// 取证用法：需要确认 hook 是否命中、调用方是谁时，可把下面的
// onLeave 改写逻辑换成 Interceptor.attach + console.log 打印
// this.returnAddress / Process.findModuleByAddress(this.returnAddress)。
var PARENT_MODE = false;

(function () {
  // ---------- 架构伪装 ----------
  var addr = null;
  try { addr = Module.findGlobalExportByName('IsWow64Process2'); } catch (e) {}
  if (!addr) { try { addr = Module.findExportByName(null, 'IsWow64Process2'); } catch (e) {} }
  if (!addr) { try { addr = Module.findExportByName('kernelbase.dll', 'IsWow64Process2'); } catch (e) {} }

  if (!addr) {
    console.log('[-] IsWow64Process2 not found');
    return;
  }

  var mod = Process.findModuleByAddress(addr);
  console.log('[*] IsWow64Process2 @ ' + addr + ' (' + (mod ? mod.name : '?') + ')');

  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.pProcessMachine = args[1];
      this.pNativeMachine = args[2];
    },
    onLeave: function (retval) {
      try {
        if (this.pProcessMachine && !this.pProcessMachine.isNull()) this.pProcessMachine.writeU16(0);
        if (this.pNativeMachine && !this.pNativeMachine.isNull()) this.pNativeMachine.writeU16(0x8664);
        retval.replace(1);
        console.log('[*] spoofed IsWow64Process2 -> NM=0x8664');
      } catch (e) {
        console.log('[-] spoof failed: ' + e);
      }
    }
  });
  console.log('[*] architecture spoof ready');

  // ---------- 外层模式：挂起 /SL5= 子进程并上报 ----------
  if (PARENT_MODE) {
    var cpAddr = Module.findGlobalExportByName('CreateProcessW');
    Interceptor.attach(cpAddr, {
      onEnter: function (args) {
        this.pi = args[9];
        try {
          this.appName = args[0].isNull() ? null : args[0].readUtf16String();
          this.cmd = args[1].isNull() ? null : args[1].readUtf16String();
        } catch (e) {
          this.cmd = null;
        }
        this.suspend = !!this.cmd && this.cmd.indexOf('/SL5=') !== -1;
        if (this.suspend) {
          // args[5] 是 dwCreationFlags 的值（x64 栈参数），回写修改后的值
          var flags = args[5].toUInt32();
          args[5] = ptr(flags | 0x4); // CREATE_SUSPENDED
          this.flags = flags;
          console.log('[*] CreateProcessW intercepted (/SL5= child), flags '
            + flags + ' -> ' + (flags | 0x4));
        }
      },
      onLeave: function (retval) {
        if (!this.suspend) return;
        if (retval.toInt32() !== 0 && !this.pi.isNull()) {
          var pid = this.pi.add(16).readU32();
          send({
            event: 'child_suspended',
            pid: pid,
            cmdline: this.cmd,
            appName: this.appName
          });
          console.log('[*] child suspended pid=' + pid);
        } else {
          console.log('[-] CreateProcessW failed to create /SL5= child');
        }
      }
    });
    console.log('[*] CreateProcessW /SL5= suspend interception ready (PARENT_MODE)');
  }
})();
