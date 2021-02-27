import frida
import sys

TAINT_WRITTEN   = 0x1
TAINT_FREED     = 0x2

shadow_memory = {}

def untaint_data(address, length, taint):
    print("[+] Untainting: 0x%x - 0x%x (%d bytes)"\
        % (address, address + length - 1, length))

    addr = address
    while (addr < (address + length)):
        try:
            shadow_memory[addr] &= ~taint
        except KeyError:
            addr = addr # wasn't tainted, nop
        addr += 1
    return
   
def taint_data(address, length, taint):
    print("[+] Tainting (%d): 0x%x - 0x%x (%d bytes)"\
        % (taint, address, address + length - 1, length))

    addr = address
    while (addr < (address + length)):
        try:
            shadow_memory[addr] ^= taint
        except KeyError:
            shadow_memory[addr] = taint
        addr += 1
    return

def die(msg, **kwargs):
     address = kwargs.get("_addr", None)
     length = kwargs.get("_len", None)
     print("\n>>>>> %s VULN DETECTED !!!!!" % msg)
     print(">>>>> DETECTED HERE ---> 0x%x" % address)

def check_taint(address, length, taint):
    print("[+] Checking taint: 0x%x - 0x%x (%d bytes)"\
        % (address, address + length - 1, length))
    addr = address
    while (addr < (address + length)):
        try:
            tag = shadow_memory[addr]
            if (tag & taint):
                return True
                break;
        except KeyError:
            addr = addr # nop

        addr += 1
    return False

def on_message(message, data):
    if (message["type"] == "error"):
        print(message["stack"])
        return
    elif (message["type"] == "send"):
        #if (message["payload"] == "abort"):
        #    print("Aborting program")
        #    frida.kill(pid)
        source    = message["payload"].split(":")[0]
        address   = int(message["payload"].split(":")[1], 16)
        length    = int(message["payload"].split(":")[2], 16)

        # If the string length is 0
        # Preparation of subsequent routines
        if (length == 0): length = 1

        if (source == "fgets"):
            taint_data(address, length, TAINT_WRITTEN)
        elif (source == "printf"):
            if (check_taint(address, length, TAINT_WRITTEN)):
                die("FORMAT STRING", _addr=address, _len=length)
        elif (source == "malloc"):
            untaint_data(address, length, TAINT_FREED)
        elif (source == "free"):
            if (check_taint(address, length, TAINT_FREED)):
                die("DOUBLE FREE", _addr=address, _len=length)
            else:
                taint_data(address, length, TAINT_FREED)
        elif (source == "read"):
            taint_data(address, length, TAINT_WRITTEN)

code = open("scr.js", "r").read()

pid = frida.spawn([sys.argv[1]])
session = frida.attach(pid)
script = session.create_script(code)

script.on("message", on_message)
script.load()

frida.resume(pid)

sys.stdin.read()
