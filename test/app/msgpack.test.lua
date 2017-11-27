buffer = require 'buffer'
msgpack = require 'msgpack'

-- Arguments check.
buf = buffer.ibuf()
msgpack.encode()
msgpack.encode('test', 'str')
msgpack.encode('test', buf.buf)
msgpack.decode()
msgpack.decode(123)
msgpack.decode(buf)
msgpack.decode(buf.buf, 'size')
msgpack.decode('test', 0)
msgpack.decode('test', 5)
msgpack.decode('test', 'offset')
msgpack.decode_unchecked()
msgpack.decode_unchecked(123)
msgpack.decode_unchecked(buf)
msgpack.decode_unchecked('test', 0)
msgpack.decode_unchecked('test', 5)
msgpack.decode_unchecked('test', 'offset')

-- Encode/decode a string.
s = msgpack.encode({1, 2, 3}) .. msgpack.encode({4, 5, 6})
obj, offset = msgpack.decode(s)
obj
obj, offset = msgpack.decode(s, offset)
obj
offset == #s + 1
obj, offset = msgpack.decode_unchecked(s)
obj
obj, offset = msgpack.decode_unchecked(s, offset)
obj
offset == #s + 1

-- Encode/decode a buffer.
buf = buffer.ibuf()
len = msgpack.encode({1, 2, 3}, buf)
len = msgpack.encode({4, 5, 6}, buf) + len
buf:size() == len
orig_rpos = buf.rpos
obj, rpos = msgpack.decode(buf.rpos, buf:size())
obj
buf.rpos = rpos
obj, rpos = msgpack.decode(buf.rpos, buf:size())
obj
buf.rpos = rpos
buf:size() == 0
buf.rpos = orig_rpos
obj, rpos = msgpack.decode_unchecked(buf.rpos, buf:size())
obj
buf.rpos = rpos
obj, rpos = msgpack.decode_unchecked(buf.rpos, buf:size())
obj
buf.rpos = rpos
buf:size() == 0

-- Invalid msgpack.
s = msgpack.encode({1, 2, 3})
s = s:sub(1, -2)
msgpack.decode(s)
buf = buffer.ibuf()
msgpack.encode({1, 2, 3}, buf)
msgpack.decode(buf.rpos, buf:size() - 1)
