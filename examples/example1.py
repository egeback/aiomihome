import sys
import re
import asyncio
import logging

sys.path.insert(0,"../") # prefer local version
sys.path.insert(0,"./") # prefer local version
sys.path.insert(0,"./aiomihome") # prefer local version
sys.path.insert(0,"../aiomihome") # prefer local version
sys.path.append("../aiomihome")
sys.path.append("./aiomihome")

from aiomihome.service import XiaomiService
from aiomihome.helpers import encode_light_rgb

def main(key):
    loop = asyncio.get_event_loop()

    #loop.set_debug(True)
    logging.basicConfig(level=logging.DEBUG)

    myhome = XiaomiService(gateways_config = [{'key': key}],loop=loop)

    try:
        loop.run_until_complete(myhome.discover())
        light = None
        gateway = None
        for (_, gw) in myhome.gateways.items():
            gateway = gw
            for key, devices in gw.devices.items():
                if key == 'light':
                    for device in devices:
                        if device['model'] ==  'gateway':
                            light = device

        if light is not None:
            #loop.run_until_complete(gateway.write_data(device['sid'], **{'rgb': 1694451968}))
            loop.run_until_complete(gateway._write_data(device['sid'], **{'rgb': encode_light_rgb(10, 255,0,0)}))

        loop.run_forever()
        
    except KeyboardInterrupt:
        loop.run_until_complete(myhome.close())
        for task in asyncio.Task.all_tasks():
            print("cancel")
            task.cancel()
        loop.close()

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv[1]))
    else:
        print("No key provided")