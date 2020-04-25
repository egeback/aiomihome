import aiounittest
import asyncio
import json
import os
import logging


from aiomihome.service import XiaomiService

class open_gateway():
    def __init__(self, ip_addr, sid, key): 
        self.service = XiaomiService()
        self.ip_addr = ip_addr
        self.sid = sid
        self.key = key
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.service.close()
    
    async def __aenter__(self):
        await self.service.listen()
        self.gateway = await self.service.add_gateway(self.ip_addr, self.sid, self.key)
        return self.gateway
    

class TestService(aiounittest.AsyncTestCase):
    def get_event_loop(self):
        #logging.basicConfig(level=logging.DEBUG)
        self.my_loop = asyncio.get_event_loop()
        return self.my_loop
    
    def get_gateway_config(self):
        dir = os.path.dirname(os.path.abspath(__file__))
        with open(dir + "/gateway_config.json", mode='r') as f:
            contents = f.read()
            j = json.loads(contents)
            return j.get("ip_addr"), j.get("sid"), j.get("key"), j.get("proto")
    
    async def test_devices(self):
        ip_addr, sid, key, proto = self.get_gateway_config()

        async with open_gateway(ip_addr, sid, key) as gateway:
            await gateway.listen()
            for device_type, devices in gateway.devices.items():
                if device_type == "sensor":
                    for device in devices:
                        if device["model"] == "gateway":
                            self.assertEqual(device["sid"], sid)
                            self.assertEqual(device["proto"], proto)
                            self.assertTrue("raw_data" in device)
                            self.assertEqual(device["raw_data"]["cmd"], "read_ack")
                            self.assertTrue("rgb" in device["data"])
                if device_type == "sensor":
                    for device in devices:
                        if device["model"] == "gateway":
                            self.assertEqual(device["sid"], sid)
                            self.assertEqual(device["proto"], proto)
                            self.assertTrue("raw_data" in device)
                            self.assertEqual(device["raw_data"]["cmd"], "read_ack")
                            self.assertTrue("rgb" in device["data"])
    
    async def test_device_callback(self):
        ip_addr, sid, key, _ = self.get_gateway_config()

        on = asyncio.Event()
        off = asyncio.Event()

        async def device_callback(resp):
            data = json.loads(resp["data"])
            if data["rgb"] == 1694498815:
                on.set()
            else:
                off.set()

        async with open_gateway(ip_addr, sid, key) as gateway:
            gateway.device_callback = device_callback
            await gateway.listen()

            await gateway.turn_off_light()
            off = asyncio.Event()
            await gateway.set_color(255, 255, 255, 255)
            await asyncio.wait_for(on.wait(), timeout=10)
            await gateway.turn_off_light()
            await asyncio.wait_for(off.wait(), timeout=10)