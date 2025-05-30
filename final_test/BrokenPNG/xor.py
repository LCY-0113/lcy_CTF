import random

with open("secret.png", "rb") as f:
    data = f.read()

# 16字节
key = random.randbytes(16)

new_data = []

for i in range(len(data)):
    new_data.append(data[i] ^ key[i % len(key)])
with open("broken.png", "wb") as f:
    f.write(bytes(new_data))

