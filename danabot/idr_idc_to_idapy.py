import re
import sys

fp = open(sys.argv[1], "r")
map_data = fp.readlines()
fp.close()

for i, line in enumerate(map_data):
    if "MakeName" in line:
        match = re.search(r'\((?P<addr>0x[0-9a-fA-F]+),\s*"(?P<name>[^"]+)"', line)
        if not match:
            pass

        else:
            addr = match.groupdict()["addr"]
            name = match.groupdict()["name"]

            name = re.sub(r'[^a-zA-Z0-9]', '_', name)
            if not name:
                pass

            print("set_name(%s, \"idr%d_%s\", 0x0)" % (addr, i, name))
