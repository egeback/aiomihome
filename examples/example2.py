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

async def start(key):
    # service = XiaomiService(gateways_config=[{"host": "10.0.4.104", "sid": "7811dcb07917", "port": 9898, "key": key}])
    service = XiaomiService(gateways_config=[{"host": "10.0.4.104", "port": 9898, "key": key}])
    #service = XiaomiService(gateways_config=[{"key": key}])
    await service.listen()
    
    gateways = await service.discover()
    gateway = gateways[0]
    print("Number of gateways found: {}".format(len(gateways)))

    #gateway = await service.add_gateway("10.0.4.104", 9898, "7811dcb07917", key)

    gateway.heartbeat_callback = heartbeat_callback
    gateway.device_callback = device_callback

    try:
        print("Turn on light")
        for device_type, devices in gateway.devices.items():
            print(device_type, len(devices))
            for device in devices:
                print("     ", device['model'])
                for value_key, value in device['data'].items():
                    print("         ", value_key, value)
        #await gateway.send_cmd(**{"mid": 11, "vol": 50})
        await light_show(gateway)
        print("Wait 10 sec")
        await asyncio.sleep(10)
        print("Start again")
        await light_show(gateway)
        print("Wait 10 sec")
        await asyncio.sleep(10)
        await gateway.turn_off_light()
    except Exception:
        traceback.print_exc(file=sys.stdout)

async def light_show(gateway):
        await gateway.send_cmd(**{"rgb": 820904191})
        await asyncio.sleep(1)
        await gateway.send_cmd(**{"rgb": 65929471})
        await asyncio.sleep(1)
        await gateway.set_color(255, 0, 0)
        await asyncio.sleep(1)
        await gateway.set_color(0, 255, 0)
        await asyncio.sleep(1)
        await gateway.set_color(0, 0, 255)
        await asyncio.sleep(1)
        print("Turn off light")
        await gateway.turn_off_light()

def main(key):
    loop = asyncio.get_event_loop()
    #loop.set_debug(True)
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    try:
        loop.run_until_complete(start(key))
        loop.run_forever()
        loop.close()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    if len(sys.argv) > 1:
        sys.exit(main(sys.argv[1]))
    else:
        print("No key provided")
