# Encoded By PyEncryptor
# A Product Of ToxicNoob
# https://github.com/Toxic-Noob

import marshal, base64, zlib
exec(marshal.loads(zlib.decompress(base64.b64decode(b'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'))))