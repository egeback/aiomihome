import asyncio
import logging
import traceback
import sys
import re

sys.path.insert(0,"../") # prefer local version
sys.path.insert(0,"./") # prefer local version
sys.path.append("../aiomihome")
sys.path.append("./aiomihome")


from aiomihome.service import XiaomiService
from aiomihome.gateway import MiHomeGateway, encode_light_rgb, parse_data, decode_light_rgb


async def heartbeat_callback(data):
    print("HEARTBEAT RECIVED", data)

async def device_callback(data):
    print("Device data RECIVED", data)

global service
service = None

async def start(key):
    global service
    service = XiaomiService(gateways_config=[{"key": key}])
    await service.listen()
    gateway = await service.add_gateway("10.0.4.104", "7811dcb07917", key, port=9898)

    gateway.heartbeat_callback = heartbeat_callback
    gateway.device_callback = device_callback

    try:
        for device_type, devices in gateway.devices.items():
            print(device_type, len(devices))
            for device in devices:
                print("     ", device['model'])
                print(device)
                for value_key, value in device['data'].items():
                    print("         ", value_key, value)
        for mid in range(29):
            await gateway.play_sound(mid, 5)
            await asyncio.sleep(2)
    except Exception:
        traceback.print_exc(file=sys.stdout)

async def close():
    await service.close()

def main(key):
    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.DEBUG)
    try:
        loop.run_until_complete(start(key))
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    
    loop.run_until_complete(close())
    loop.close()

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv[1]))
    else:
        print("No key provided")
