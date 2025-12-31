import sys
import time
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import RegDump32

if len(sys.argv) != 4:
    print("Usage: python qilin_bypass.py <x64dbg_path> <sample_exe_path> <sample_run_params>")
    quit(1)

x64dbg_exe_path = x64dbg_path=sys.argv[1]
sample_exe_path = x64dbg_path=sys.argv[2]
sample_run_params = x64dbg_path=sys.argv[3]

# Session #1 for applying x64dbg parameters
print('[+] Creating a new x64dbg Automate session')
client = X64DbgClient(x64dbg_exe_path)
client.start_session(f'{sample_exe_path}',
    f'{sample_run_params}'
)

client.set_setting_int('Engine', 'NoScriptTimeout', 1)
client.set_setting_int('Events', 'TlsCallbacks', 0)
client.set_setting_int('Events', 'TlsCallbacksSystem', 0)
client.set_setting_int('Events', 'SystemBreakpoint', 0)

old = client.get_setting_str("Exceptions", "IgnoreRange")
new = old + ",000006BA-000006BA:second:log:debuggee"
client.set_setting_str("Exceptions", "IgnoreRange", new)

client.terminate_session()

# 3 sec pause to successfully close x64dbg
time.sleep(3)

client.start_session(f'{sample_exe_path}',
    f'{sample_run_params}'
)

client.clear_breakpoint()
client.cmd_sync(f"scriptload d:\RmRegisterResources_hook.txt")

client.cmd_sync("bp msvcrt.memcmp")
client.cmd_sync("bpcnd msvcrt.memcmp, arg.get(2)==40")

client.go()
client.wait_until_stopped()
client.cmd_sync("memcpy arg.get(0), arg.get(1), arg.get(2)")

client.clear_breakpoint()

client.cmd_sync("bp RmRegisterResources")
dp32_condition = r'strstr(utf16(ECX)\, \".dp32\")'
client.cmd_sync(f"bpcnd RmRegisterResources, {dp32_condition}")

client.cmd_sync(f"bpcommand RmRegisterResources, \"scriptcmd call mycallback\"")
client.go()

client.detach_session()