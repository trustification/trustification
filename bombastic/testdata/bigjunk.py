import bz2

CHUNKS=int(1000000/2)
CHUNKSIZE=100000
data = b'{' * CHUNKSIZE
data2 = b'}' * CHUNKSIZE
size = 0

with bz2.open('./bigjunk.bz2', 'wb') as f:
    for _ in range(CHUNKS):
        f.write(data)
        size += CHUNKSIZE

    f.write(b'"a":1"')

    for _ in range(CHUNKS):
        f.write(data2)
        size += CHUNKSIZE

print(f'{size=}')
