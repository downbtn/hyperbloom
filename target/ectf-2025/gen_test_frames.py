#!/usr/bin/env python3
from ectf25_design.encoder import Encoder
from ectf25.utils.decoder import DecoderIntf

with open("global.secrets", "r") as f:
    secrets = f.read()

enc = Encoder(secrets)
dec = DecoderIntf("/dev/ttyACM0")

for i in range(500):
    ts = 100 + i
    frame = f"{i:04d}" * 16
    enc_frame = enc.encode(channel=1, frame=frame.encode('ascii'), timestamp=ts)

    dec.decode(enc_frame)
