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
        self.my_loop = asyncio.get_event_loop()
        return self.my_loop
    
    def get_gateway_config(self):
        dir = os.path.dirname(os.path.abspath(__file__))
        with open(dir + "/gateway_config.json", mode='r') as f:
            contents = f.read()
            j = json.loads(contents)
            return j.get("ip_addr"), j.get("sid"), j.get("key"), j.get("proto")

    async def test_discovery(self):
        ip_addr, sid, key, proto = self.get_gateway_config()
        
        service = XiaomiService(gateways_config=[{"key": key}], loop=self.get_event_loop())

        gateways = await service.discover()
        self.assertEqual(len(gateways), 1)
        self.assertEqual(gateways[0].ip_address, ip_addr)
        self.assertEqual(gateways[0].sid, sid)
        self.assertEqual(gateways[0].proto, proto)

        await service.close()

    
    async def test_direct_connect(self):
        ip_addr, sid, key, _ = self.get_gateway_config()

        async with open_gateway(ip_addr, sid, key) as gateway:
            await gateway.listen()
    
    async def test_heartbeat(self):
        ip_addr, sid, key, _ = self.get_gateway_config()

        event = asyncio.Event()

        async def heartbeat_callback(data):
            event.set()

        async with open_gateway(ip_addr, sid, key) as gateway:
            gateway.heartbeat_callback = heartbeat_callback
            await gateway.listen()
            await asyncio.wait_for(event.wait(), timeout=10)
    
    async def test_no_connection(self):
        failure = False
        try:
            service = XiaomiService()
            await service.listen()
            logging.basicConfig(level=logging.CRITICAL)
            self.gateway = await service.add_gateway("192.168.99.99", "", "")
        except Exception as e:
            self.assertTrue(str(e), "No response from Gateway")
            failure = True
        finally:
            await service.close()
        
        logging.basicConfig(level=logging.ERROR)
        self.assertTrue(failure)
