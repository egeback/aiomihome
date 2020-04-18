import asyncio

def run_callback(loop, callback, *args, **kwargs):
    if asyncio.iscoroutine(callback):
            loop.create_task(callback)
    elif asyncio.iscoroutinefunction(callback):
        loop.create_task(callback(*args, **kwargs))
    else:
        loop.run_in_executor(None, callback, args, kwargs)

def _list2map(data):
    if not isinstance(data, list):
        return data
    new_data = {}
    for obj in data:
        for key in obj:
            new_data[key] = obj[key]
    new_data['raw_data'] = data
    return new_data


def encode_light_rgb(brightness, red, green, blue):
    """Encode rgb value used to control the gateway light"""
    return (brightness << 24) + (red << 16) + (green << 8) + blue

def decode_light_rgb(c):
    bri = (c>>24)&0xff;
    r = (c>>16)&0xff;
    g = (c>>8)&0xff;
    b = c&0xff;

    return {"brightness": bri, "red": r, "green": g, "blue": b}