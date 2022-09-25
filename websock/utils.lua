--[[
MIT License

Copyright (c) 2022 nikneym

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

local buffer = require "string.buffer"
local bs64   = require "mbedtls.base64"
local bit    = require "bit"

local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local random = love and love.math.random or math.random
local char = string.char
local concat = table.concat

local Pack, Upack do
  if love then
    Pack = love.data.pack
    Upack = love.data.unpack
  else
    local v = tonumber(_VERSION:match("(%d%.%d)"))
    if v > 5.2 then
      Pack = string.pack
      Upack = string.unpack
    else
      local ok, str = pcall(require, "compat53.string")
      assert(ok, "compat53 module is needed on versions below 5.2")
      Pack = str.pack
      Upack = str.unpack
    end
  end
end

--- returns mask key both as table and string
--- @return string
local function Key(mask)
  for i = 1, 4 do
    mask[i] = random(32)
  end

  return char(mask[1], mask[2], mask[3], mask[4])
end

--- returns a base64 encoded string for "Sec-WebSocket-Key" header
--- @return string
local function SecWSKey()
  local buf = { }
  for i = 1, 16 do
    buf[i] = random(32, 127)
  end

  local raw = char(
    buf[1],  buf[2],  buf[3],  buf[4],
    buf[5],  buf[6],  buf[7],  buf[8],
    buf[9],  buf[10], buf[11], buf[12],
    buf[13], buf[14], buf[15], buf[16]
  )

  buf = nil
  return bs64.encode(raw)
end

--- WS headers
--- @param addr table
--- @return table
local function CreateHeaders(addr)
  return {
    ("GET %s HTTP/1.1\r\n"):format(addr.path),
    ("Host: %s\r\n"):format(addr.authority),
    "Upgrade: websocket\r\n",
    "Connection: Upgrade\r\n",
    ("Sec-WebSocket-Key: %s\r\n"):format(SecWSKey()),
    "Sec-WebSocket-Version: 13\r\n",
  }
end

--- @param opcode number
--- @param key table
--- @param mask string
--- @param buf string.buffer
--- @param data string
--- @return string
local function FrameBuilder(opcode, key, mask, buf, data)
  local fin = char(bor(opcode, 0x80))
  buf:put(fin)

  if not data then
    buf:put(char(0x80), mask)
    return buf:tostring()
  end

  local len = #data
  if len <= 125 then
    buf:put(char(bor(len, 0x80)))
  elseif len <= 65535 then
    buf:put(char(bor(126, 0x80)))
    buf:put(Pack(">I2", len))
  else
    buf:put(char(bor(127, 0x80)))
    buf:put(Pack(">I8", len))
  end

  -- append the key (mask info)
  buf:put(mask)

  -- append masked data
  for i = 1, len do
    local c = char(bxor(data:byte(i), key[(i - 1) % 4 + 1]))
    buf:put(c)
  end

  return buf:tostring()
end

local function ReceiveFrameInfo(handle)
  local data, err = handle:receive(2)
  if not data then
    return nil, nil, nil, err
  end

  local b1, b2 = data:byte(1, 2)

  -- First Byte
  local FIN    = band(b1, 0x80) ~= 0
  local RSV1   = band(b1, 0x40) ~= 0
  local RSV2   = band(b1, 0x20) ~= 0
  local RSV3   = band(b1, 0x10) ~= 0
  local opcode = band(b1, 0x0F)

  -- Second Byte
  local mask   = band(b2, 0x80) ~= 0
  local length = band(b2, 0x7F)

  assert(mask == false, "server can't send a masked message")
  return length, FIN, opcode, nil
end

local function ReceiveFullLength(handle, length)
  if length == 126 then
    local data, err = handle:receive(2)
    if not data then
      return nil, err
    end

    local len = Upack(">I2", data)
    return len, nil
  end

  if length == 127 then
    local data, err = handle:receive(8)
    if not data then
      return nil, err
    end

    local len = Upack(">I8", data)
    return len, nil
  end

  return length, nil
end

local function ReceiveFrame(handle)
  local length, FIN, opcode, err = ReceiveFrameInfo(handle)
  if err then
    return err
  end

  length, err = ReceiveFullLength(handle, length)
  if err then
    return err
  end

  local data, part
  local buf = buffer.new(length)
  local bufLen = 0

  repeat
    data, err, part = handle:receive(length - bufLen)
    local result = data or part

    if result then
      buf:put(result)
      bufLen = bufLen + #result
    end
  until bufLen == length

  return buf, FIN, opcode
end

return {
  Key = Key,
  CreateHeaders = CreateHeaders,
  FrameBuilder = FrameBuilder,
  ReceiveFrame = ReceiveFrame,
}