import base64
import hashlib
import os
from pathlib import Path
import time

sd="keys"

base=['!', '#', '$', '%', '&', '(', ')', '*', '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~']

ultra=['а', 'б', 'в', 'г', 'д', 'е', 'ж', 'з', 'и', 'й', 'к', 'л', 'м', 'н', 'о', 'п', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я', 'ё', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',"-"]

a='─━│┃┄┅┆┇┈┉┊┋┌┍┎┏┐┑┒┓└┕┖┗┘┙┚┛├┝┞┟┠┡┢┣┤┥┦┧┨┩┪┫┬┭┮┯┰┱┲┳┴┵┶┷┸┹┺┻┼┽┾┿╀╁╂╃╄╅╆╇╈╉╊╋╌╍╎╏═║╪╫╬'
ultra=list(a)
def base2ultra(s):
	n=""
	for i in s:
		n+=ultra[base.index(i)]
	return n
def ultra2base(s):
	n=""
	for i in s:
		n+=base[ultra.index(i)]
	return n


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

random.seed(input(">"))
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


def pub2name(pub):
	return onion_address_from_public_key(pub)

def verif_frame(sig,data):
	print(data)
	pub,dat=data[:32],data[32:]
	vk=VerifyKey(pub)
	try:
		ver=vk.verify(data,sig)
	except:
		return None,None
	return pub2name(ver[:32]),ver[32:]

def sign(data):
	return k.sign(data)[:64]

def make_frame(data):
	return base64.b32encode(sign(k.verify_key.encode()+data)),k.verify_key.encode()+data

import re
from requests_tor import RequestsTor
rt = RequestsTor(tor_ports=(9050,))

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
	r=rt.get("http://"+url+"/"+file).text
	s,d=base64.b32decode(file.split(".html",1)[0]),r.encode()
	#print([s,d])
	_,_=verif_frame(s,d)
	assert _
	#print(file)
	if _: open(f"database/{file}","wb").write(d)

def sync():
	urls=set()
	for i in os.listdir("database"):
		urls.update({pub2name(open(f"database/{i}","rb").read()[:32])})
	print("🌐 Sync with",len(urls),"nodes")
	for url in list(urls):
		print("Sync with",url)
		try:
			c=catalouge(url)
		except Exception as e:
			print("⛔ Malformed or fake domain",url,e)
			continue
		u=list(unknown(c))
		for i in u:
			try:
				copy(url,i)
				print("✅ Loaded",i)
			except Exception as e: print("🔇 Malformed",i,e)

def cycle():
	import subprocess as s
	s.Popen(["tor","-f","torrc"])
	s.Popen(["python","-m","http.server","8765","-d","database"])
	for i in range(10,-1,-1):
		print(i,"... Repka is starting")
		time.sleep(1)
	while 1:
		sync()
		time.sleep(1)

def add(data):
	name,dat=make_frame(data)
	#print([name,dat])
	open(f"database/{name.decode()}.html","wb").write(dat)

if __name__=="__main__":
	add("<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"><br><br><h1>I am alive!</h1>This is my simple Repka card.<br>If you see it in your database, probably you will sync with me in some time ❤️".encode())
	cycle()
