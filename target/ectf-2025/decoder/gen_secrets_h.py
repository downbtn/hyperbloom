#!/usr/bin/env python3
import json
from base64 import b64decode

print("Generating secrets.h")

def bytes_to_char(b: bytes) -> str:
    return "{" + ", ".join([f"0x{byte:02x}" for byte in b]) + "}"

with open("/global.secrets", "r") as f:
    secrets = json.load(f)

subscription_key = bytes_to_char(b64decode(secrets["subscription_key"]))
emergency_key = bytes_to_char(b64decode(secrets["emergency_key"]))

header = f"""#include <stdint.h>

static const uint8_t SUBSCRIPTION_KEY[] = {subscription_key};
static const uint8_t EMERGENCY_KEY[] = {emergency_key};
"""

with open("/decoder/inc/secrets.h", "w") as f:
    f.write(header)

print("secrets.h written")
