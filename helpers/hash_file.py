import hashlib
import logging

def hash_file(file):
    chunk_size = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(file, 'rb') as f:
            while True:
                chk = f.read(chunk_size)
                if not chk:
                    break
                md5.update(chk)
                sha1.update(chk)
                sha256.update(chk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except PermissionError:
        print(f"PermissionError Accessing File: {file}")
        return "ERROR", "ERROR","ERROR"
    except :
        print(f"General Error Hashing File: {file}")
        return "ERROR", "ERROR","ERROR"