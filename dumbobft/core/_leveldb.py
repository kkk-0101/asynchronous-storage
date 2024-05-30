import leveldb
import hashlib

def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()

def _write(i, key, m):
    try:
        path = "./db/db" + str(i)
        #print("key----"+key)
        db = leveldb.LevelDB(path)
        db.Put(key, m)
        #print(db3.Get(key ).decode('utf-8'))
    except:
        print("db NO write ",path)
    
def _read(i, key):
    try:
        path = "./db/db" + str(i)
        db = leveldb.LevelDB(path)
        m = db.Get(key)
        return m
    except:
        print("db NO read ",key)
