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

local TLSSocket = require "websock.tlssocket"
local socket    = require "socket"
local buffer    = require "string.buffer"

local shl, shr, band do
  local bit = require "bit"
  shl = bit.lshift
  shr = bit.rshift
  band = bit.band
end

local Key, CreateHeaders, FrameBuilder, ReceiveFrame, parse do
  local utils = require "websock.utils"
  local url = require "socket.url"

  parse = url.parse
  CreateHeaders = utils.CreateHeaders
  FrameBuilder = utils.FrameBuilder
  ReceiveFrame = utils.ReceiveFrame
  Key = utils.Key
end

local tcp = socket.tcp
local char = string.char
local insert = table.insert
local remove = table.remove
local concat = table.concat

local op = {
  continue = 0x0,
  text = 0x1,
  -- 3 to 7 are reserved for further non-control frames
  binary = 0x2,
  close = 0x8,
  ping = 0x9,
  pong = 0xa
  -- B to F are reserved for further control frames
}

local Client = { version = "0.1.0" }
Client.__index = Client

function Client.new(address)
  assert(address, "address is not specified")
  local addr = parse(address)
  assert(addr.scheme == "ws" or addr.scheme == "wss",
  "unknown scheme")

  addr.path = addr.path or "/"
  local isTLS = addr.scheme == "wss"
  addr.port = addr.port or isTLS and 443 or 80
  local handle = isTLS and TLSSocket.new() or tcp()
  local mask = { }

  return setmetatable({
    isConnected = false,
    headers     = CreateHeaders(addr),
    handle      = handle,
    isTLS       = isTLS,
    addr        = addr,
    key         = mask,
    buf         = buffer.new(1024),
    ["mask"]    = Key(mask),
  }, Client)
end

function Client:__tostring()
  return "websock.client"
end

function Client:set(k, v)
  insert(self.headers, ("%s: %s\r\n"):format(k, v))
  return self
end

function Client:initConnection()
  -- TCP connection
  local ok, err = self.handle:connect(self.addr.host, self.addr.port)
  if not ok then
    return err
  end

  -- initialization message
  insert(self.headers, "\r\n")
  local req = concat(self.headers)
  local msg_len = #req

  -- send WS request
  local len, err = self.handle:send(req)
  if len ~= msg_len then
    return err
  end

  self.isConnected = true

  return nil
end

function Client:receiveResponse()
  local headers = { }

  local data, err
  while data ~= "" do
    data = self.handle:receive()
    if err then
      return nil, err
    end

    if #data == 0 then
      break
    end

    local k, v = data:match("(.-)%:%s(.+)")
    if k then
      headers[k] = v
    end
  end

  return headers, nil
end

local function send(self, code, data)
  local m = FrameBuilder(code, self.key, self.mask, self.buf, data)
  local len, err = self.handle:send(m)
  if len ~= #m then
    return nil, err
  end

  self.buf:reset()
  return len, nil
end

function Client:close(code, msg)
  if code and msg then
    send(self, op.close, char(shr(code, 8), band(code, 0xff)) .. msg)
  else
    send(self, op.close, nil)
  end

  self.buf:reset()
  self.buf:free()
  self.handle:close()
  self.isConnected = false

  self:onClose()
end

function Client:ping(msg)
  return send(self, op.ping, msg)
end

function Client:pong(msg)
  return send(self, op.pong, msg)
end

function Client:send(msg)
  return send(self, op.text, msg)
end

function Client:run()
  local err = self:initConnection()
  if err then
    return error(err)
  end

  -- on connection
  do
    local headers, err = self:receiveResponse()
    if not headers then
      return error(err)
    end

    self:onConnect(headers)
  end

  -- on data received
  while self.isConnected do
    local buf, FIN, opcode = ReceiveFrame(self.handle)

    if opcode == op.close then
      print "closed"
      self:close()
      break
    end

    if not FIN then
      local _buf, _FIN, _opcode
      repeat
        _buf, _FIN, _ = ReceiveFrame(self.handle)
        if _buf then
          buf:put(_buf)
        end
      until _FIN
    end

    if opcode == op.text then
      self:onMessage(buf)
    end

    if opcode == op.ping then
      self:onPing(buf)
    end

    if opcode == op.pong then
      self:onPong(buf)
    end

    if opcode == op.binary then
      self:onBinary(buf)
    end
  end
end

--- Gets called when WS connection is established
--- @param headers table
function Client:onConnect(headers)
end

--- Gets called when a text message is received
--- @param data string.buffer
function Client:onMessage(data)
end

--- Gets called when a binary message is received
--- @param data string.buffer
function Client:onBinary(data)
end

--- Gets called when a ping is received
--- @param data string.buffer
function Client:onPing(data)
end

--- Gets called when a pong is received
--- @param data string.buffer
function Client:onPong(data)
end

--- Gets called when connection is closed
function Client:onClose()
end

return Client