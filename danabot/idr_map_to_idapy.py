import re
import sys

fp = open(sys.argv[1], "r")
map_data = fp.readlines()
fp.close()

for i, line in enumerate(map_data):
    match = re.match(r'^\s\S+\s(?P<name>\S+)_(?P<addr>[0-9a-fA-F]+)\s+$', line)
    if match:
        addr = match.groupdict()["addr"]
        name = match.groupdict()["name"]

        name = re.sub(r'[^a-zA-Z0-9]', '_', name)

        print("current_name = get_name(0x%s)" % addr)
        print('if current_name and current_name.startswith("sub_"):')
        print("\tset_name(0x%s, \"idr%d_%s\", 0x0)" % (addr, i, name))
