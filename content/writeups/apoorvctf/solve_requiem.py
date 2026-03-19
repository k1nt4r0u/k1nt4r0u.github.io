#!/usr/bin/env python3

ENCODED_FLAG = bytes.fromhex(
    "3b2a3535282c392e3c21146a05176a08690508690b0f6b6917056b14050e126b"
    "6f0569020a69086b6914196927"
)
XOR_KEY = 0x5A


def main() -> None:
    flag = bytes(byte ^ XOR_KEY for byte in ENCODED_FLAG)
    print(flag.decode())


if __name__ == "__main__":
    main()