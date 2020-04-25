# aiomihome

Asyncio version of https://github.com/Danielhiversen/PyXiaomiGateway

## Description
The API only includes a thin layer with out proper handling of devices or sensors with seprate 

Library consist of two classes
* **Service**<br>
  Manage the multisocket interface to the xiaomi bridge and connecting to a gateway. Includes service for discovery of gateways

* **Gateway**<br>
  Handles the connection to the gateway


The bridge needs to be i local mode and key needs to be provided to communicate with the gateway
  
## Usage

Create a new service object. The gateway config key is required to be able to communicate with the gateway. If discovery is used and only one gateway exist only key is needed, if several provide sid or host.

See example folder for runnable code.

### Connect go gateway
#### Run auto discover:
```python
gateways_config = [
    {
      "host": "10.0.4.104", 
      "sid": "7811dcb07917",
      "port": 9898,
      "key": key
     }
]
service = XiaomiService(gateways_config=gateways_config)

# Start the mulitcast socket listner
await service.listen()

# Run the auto discover
gateways = await service.discover()

print("Number of gateways found: {}".format(len(gateways)))

# Get first gateway
gateway = gateways[0]
```

#### Directly connect to gateway:

```python
service = XiaomiService()

# Start the mulitcast socket listner
await service.listen()

# Create a gatewate connetion
gateway = await service.add_gateway("10.0.4.104", 9898, "7811dcb07917", key)
```

#### Close conections
```python
await service.close()
```

### Listners
```python
async def heartbeat_callback(data):
    print("HEARTBEAT RECIVED", data)

async def device_callback(data):
    print("Device data RECIVED", data)

gateway.heartbeat_callback = heartbeat_callback
gateway.device_callback = device_callback
```

### Interact with the gateway
#### Print devices
```python
print("Turn on light")
for device_type, devices in gateway.devices.items():
  print(device_type, len(devices))
  for device in devices:
    print("     ", device['model'])
    print(device)
      for value_key, value in device['data'].items():
        print("         ", value_key, value)
```
#### Set the gateway light
```python
# Red
await gateway.set_color(255, 0, 0)
await asyncio.sleep(1)
# Green
await gateway.set_color(0, 255, 0)
await asyncio.sleep(1)
# Blue
await gateway.set_color(0, 0, 255)
await asyncio.sleep(1)
# Off
await gateway.turn_off_light()
```
