class _Getch:
    """Gets a single character from standard input.  Does not echo to the
screen."""
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys

    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch.encode()


class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        import msvcrt
        return msvcrt.getch()


getch = _Getch()








import base64
import hashlib
import os
from pathlib import Path
import time

sd="keys"

http_local_port=8765

def expand_private_key(secret_key) -> bytes:
    hash = hashlib.sha512(secret_key[:32]).digest()
    hash = bytearray(hash)
    hash[0] &= 248
    hash[31] &= 127
    hash[31] |= 64
    return bytes(hash)


def onion_address_from_public_key(public_key: bytes) -> str:
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    onion_address = "{}.onion".format(
        base64.b32encode(public_key + checksum + version).decode().lower()
    )
    return onion_address


def verify_v3_onion_address(onion_address: str) -> list[bytes, bytes, bytes]:
    # v3 spec https://gitweb.torproject.org/torspec.git/plain/rend-spec-v3.txt
    try:
        decoded = base64.b32decode(onion_address.replace(".onion", "").upper())
        public_key = decoded[:32]
        checksum = decoded[32:34]
        version = decoded[34:]
        if (
            checksum
            != hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
        ):
            raise ValueError
        return public_key, checksum, version
    except:
        raise ValueError("Invalid v3 onion address")


def create_hs_ed25519_secret_key_content(signing_key: bytes) -> bytes:
    return b"== ed25519v1-secret: type0 ==\x00\x00\x00" + expand_private_key(
        signing_key
    )


def create_hs_ed25519_public_key_content(public_key: bytes) -> bytes:
    assert len(public_key) == 32
    return b"== ed25519v1-public: type0 ==\x00\x00\x00" + public_key


def store_bytes_to_file(
    bytes: bytes, filename: str
) -> str:
    with open(filename, "wb") as binary_file:
        binary_file.write(bytes)
    #if uid and gid:
    #    os.chown(filename, uid, gid)
    return filename


def store_string_to_file(
    string: str, filename: str
) -> str:
    with open(filename, "w") as file:
        file.write(string)
    #if uid and gid:
    #    os.chown(filename, uid, gid)
    return filename


def create_hidden_service_files(
    private_key: bytes,
    public_key: bytes
) -> None:

    #path = Path(tor_data_directory)
    #parent = path.parent.absolute()
    # these are not strictly needed but takes care of the file permissions need by tor
    #tor_user = parent.owner()
    #tor_group = parent.group()
    #uid = pwd.getpwnam(tor_user).pw_uid
    #gid = grp.getgrnam(tor_group).gr_gid
    #if not path.exists():
    #    os.mkdir(tor_data_directory)
    #    os.chmod(tor_data_directory, 0o700)
    #    os.chown(tor_data_directory, uid, gid)

    file_content_secret = create_hs_ed25519_secret_key_content(private_key)

    store_bytes_to_file(
        file_content_secret, f"{sd}/hs_ed25519_secret_key"
    )

    file_content_public = create_hs_ed25519_public_key_content(public_key)
    store_bytes_to_file(
        file_content_public, f"{sd}/hs_ed25519_public_key"
    )

    onion_address = onion_address_from_public_key(public_key)
    store_string_to_file(onion_address, f"{sd}/hostname")




from nacl.signing import SigningKey,VerifyKey
import random
import os
import time

#random.seed(input("User seed (your very-very private combination of words, which nobody can reproduce)>"))
print("User seed (your very-very private combination of words, which nobody can reproduce)")
b=""
tip=["❤️","🩷","🧡","💛","💚","💙","🩵","💜","🤎","🖤","🩶","🤍"]
while 1:
	n=getch()
	if n==b"\n" or n==b"\r":break
	b+=n.decode()
	random.seed(b)
	print("Tip: ","".join(random.sample(tip,5)),end="\r")
print("OK, lets go")
random.seed(b)
k=SigningKey(random.randbytes(32))


try:
	os.remove(f"{sd}/hs_ed25519_public_key")
except FileNotFoundError: pass
open(f"{sd}/hs_ed25519_secret_key","wb").write(b'== ed25519v1-secret: type0 ==\x00\x00\x00'+k._signing_key[:-32])
open(f"{sd}/hs_ed25519_public_key","wb").write(b'== ed25519v1-public: type0 ==\x00\x00\x00'+k.verify_key._key)
create_hidden_service_files(
        k._signing_key[:-32],  # the ed25519 private key often includes the public key, this does not
        k.verify_key._key,
    )
addr=onion_address_from_public_key(k.verify_key.encode())
print(addr)
def pub2name(pub):
	return onion_address_from_public_key(pub)

def verif_frame(sig,data):
	#print(data)
	pub=base64.b85decode(data[:40])
	vk=VerifyKey(pub)
	#print([sig,data])
	try:
		ver=vk.verify(data.encode(),sig)
	except Exception as e:
		print("Sign dоesnt match",e)
		return None,None
	return pub2name(ver[:32]),ver[32:]

def sign(data):
	return k.sign(data)[:64]

def make_frame(data:str) -> str:
	bkey=base64.b85encode(k.verify_key.encode()).decode()
	return base64.b32encode(sign(bkey.encode()+data.encode())),bkey+data

import re
import requests
from requests_tor import RequestsTor
rt = RequestsTor(tor_ports=(9050,))

def req(pth):
	r=rt.get(pth)
	r.encoding="utf-8"
	return r.text

def catalouge(url):
	files=[]
	while not files:
		res=rt.get("http://"+url).text
		files=re.findall("<li><a.*?>(.*?)<\/a><\/li>",res)
	return files
def unknown(c):
	return set([i for i in c])-set(os.listdir("database"))

#def req(url,file=""):
#	s = socks.socksocket()
#	s.set_proxy(socks.SOCKS5, "localhost",9050)
#	s.connect((url, 80))
#	s.sendall(b"GET /"+file.encode()+b" HTTP/1.0\r\n\r\n")
#	res=s.recv(4096)
#	if not file: return res
#	l=int(res.split(b"Content-Length: ",1)[1].split(b"\r",1)[0].decode())
#	return s.recv(l)

#def getfile(url,file=""):
#	r=req(url,file)
#	#print(r)
#	s,d=base64.b32decode(file.split(".html",1)[0]),r
#	print([s,d])
#	return verif_frame(s,d)

def copy(url,file):
	print("http://"+url+"/"+file)
	r=req("http://"+url+"/"+file)
	s=base64.b32decode(file.split(".html",1)[0])
	_,_=verif_frame(s,r)
	assert _
	#print(file)
	if _: open(f"database/{file}","w",encoding="utf8").write(r)

def sync():
	urls=set()
	for i in os.listdir("database"):
		urls.update({pub2name(base64.b85decode(open(f"database/{i}","r",encoding="utf-8").read()[:40]))})
	urls=urls-{addr}
	print("🌐 Repka sync",len(urls),"nodes","| Clearnet:",f"http://127.0.0.1:{http_local_port}","| Tor: http://"+addr)
	l=list(urls)
	random.shuffle(l)
	for url in l:
		print("❇️ Syncing with",url)
		try:
			c=catalouge(url)
		except Exception as e:
			print("🔇 Malformed or fake domain",url,e)
			continue
		u=list(unknown(c))
		random.shuffle(u)
		changed=False
		for i in u:
			if not (".html" in i): continue
			try:
				copy(url,i)
				print("✅ Loaded",i)
				changed=True
			except Exception as e: print("📛 Malformed",i,e)
		if not changed: print("✴️ All data is up-to-date")

def cycle():
	import subprocess as s
	s.Popen(["tor","-f","torrc"])
	s.Popen(["python","-m","http.server",str(http_local_port),"-d","database"])
	for i in range(10,-1,-1):
		print(i,"... Repka is starting")
		time.sleep(1)
	while 1:
		sync()
		time.sleep(1)

def add(data):
	name,dat=make_frame(data)
	#print([name,dat])
	open(f"database/{name.decode()}.html","w",encoding="utf-8").write(dat)

if __name__=="__main__":
	add(f"<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"><br><br><h1>I am alive!</h1>My name is {addr}<br>This is my simple Repka card.<br>If you see it in your database, probably you will sync with me in some time ❤️")
	cycle()
