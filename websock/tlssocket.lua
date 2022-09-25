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

local socket = require "socket"
local buffer = require "string.buffer"
local tls = require "mbedtls.ssl"
local picodnsOk, picodns = pcall(require, "picodns")

local co_is_yieldable = coroutine.isyieldable
local co_yield = coroutine.yield
local gettime = socket.gettime

local function read(h, n)
  local data, err, part = h:receive(n)

  if err == "closed" then
    return error "closed"
  end

  if data or part then
    return data or part
  end

  return ""
end

local function write(h, s)
  local bytes, err = h:send(s)

  if err == "closed" then
    return error "closed"
  end

  if bytes ~= nil and err == nil then
    return bytes
  end

  if not bytes or bytes < #s then
    return 0, err
  end
end

--- @class TLSSocket
--- @field handle userdata
--- @field readBuffer userdata
--- @field context userdata
local TLSSocket = {
  version = "1.0.3",
  cfg = tls.newconfig "tls-client"
}
TLSSocket.__index = TLSSocket

-- create a picodns resolver if exists
if picodnsOk then
  TLSSocket.resolver = picodns.newResolver()
end

--- Creates a new `TLSSocket` object.
--- @return TLSSocket
function TLSSocket.new()
  local handle = socket.tcp()

  return setmetatable({
    handle = handle,
    readBuffer = buffer.new(8192),
    context = tls.newcontext(TLSSocket.cfg, read, write, handle),
  }, TLSSocket)
end

function TLSSocket:__tostring()
  return tostring(self.handle)
end

--- Closes the socket and releases the TLS context and bytes buffer.
function TLSSocket:close()
  self.readBuffer:free()
  self.context:reset()
  self.handle:close()
end

local function is_ipv4(host)
  return host:find("^%d+%.%d+%.%d+%.%d+$")
end

local function is_ipv6(host)
  return host:find("^[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?[%a%d]+%:?$")
end

--- Connects the socket to the given host and port.
--- @param host string
--- @param port? number 443 is default
--- @return boolean ok
--- @return string|nil err
function TLSSocket:connect(host, port)
  assert(type(host) == "string", "host name is not specified")

  -- for host name verification
  self.context:sethostname(host)

  -- if called in a coroutine, make this socket non-blocking
  if co_is_yieldable() then
    if self.handle:gettimeout() ~= 0 then
      self.handle:settimeout(0)
    end
  end

  local hostCheck = host == "localhost"
                    or is_ipv4(host)
                    or is_ipv6(host)

  if not hostCheck then
    -- resolve host address with picodns if exists
    if picodnsOk then
      local answers, err = TLSSocket.resolver:query(host)
      if not answers then
        return false, "no such domain"
      end

      host = answers[1].content
    end
  end

  local startTime = gettime()
  repeat
    local ok, err = self.handle:connect(host, port or 443)

    if gettime() - startTime >= 3 then
      return false, "connection failed"
    end

    if co_is_yieldable() then
      co_yield()
    end
  until ok == 1

  return true, nil
end

--- Sends a message through a socket.
--- @param str any
--- @return number|nil bytesWritten
--- @return string|nil err
function TLSSocket:send(str)
  assert(str, "a buffer must be provided to send")

  if co_is_yieldable() then
    local len = #str
    repeat
      local bytesWritten, err = self.context:write(str)
      if err == "closed" then
        return nil, "connection closed"
      end
      co_yield()
    until bytesWritten == len

    return len, nil
  end

  return self.context:write(str)
end

local function read_by_length(self, length)
  -- got enough bytes in the buffer
  if #self.readBuffer >= length then
    return self.readBuffer:get(length), nil
  end

  -- not enough bytes, receive 'till get the full
  local total = length
  repeat
    local msg, err = self.context:read(length - #self.readBuffer)
    if err == "closed" then
      return nil, "connection closed"
    end

    if msg then
      self.readBuffer:put(msg)
    end

    if co_is_yieldable() then
      co_yield()
    end
  until #self.readBuffer >= length

  return self.readBuffer:get(total), nil
end

local function read_line_zero_buffer(self)
  local msg, err
  repeat
    msg, err = self.context:read(8192)
    if err == "closed" then
      return nil, "connection closed"
    end

    if co_is_yieldable() then
      co_yield()
    end
  until msg

  local msgLen = #msg

  -- temporary buffer for searching line
  local tempBuffer = buffer.new(msgLen)
  tempBuffer:set(msg)

  local ptr = tempBuffer:ref()

  local line
  for i = 0, msgLen do
    -- found a line feed '\n'
    if ptr[i] == 10 then
      if ptr[i - 1] == 13 then -- '\r'
        line = tempBuffer:get(i - 1)
        tempBuffer:skip(2)
        break
      end

      line = tempBuffer:get(i)
      tempBuffer:skip(1)
      break
    end
  end

  -- put the rest back to buffer
  self.readBuffer:put(tempBuffer)
  tempBuffer:free()

  if line then
    return line, nil
  end

  return nil, "line not found"
end

local function read_line_filled_buffer(self)
  local ptr = self.readBuffer:ref()

  local line
  for i = 0, #self.readBuffer do
    if ptr[i] == 10 then
      if ptr[i - 1] == 13 then
        line = self.readBuffer:get(i - 1)
        self.readBuffer:skip(2)
        break
      end

      line = self.readBuffer:get(i)
      self.readBuffer:skip(1)
      break
    end
  end

  if line then
    return line, nil
  end

  -- TODO: optimize and cleanup
  local msg, err
  repeat
    msg, err = self.context:read(8192)
    if err == "closed" then
      return nil, "connection closed"
    end

    if co_is_yieldable() then
      co_yield()
    end
  until msg
  self.readBuffer:put(msg)

  return nil, "failed to read line"
end

local function read_by_line(self)
  local bufferLen = #self.readBuffer

  -- got bytes in the buffer
  if bufferLen > 0 then
    local line, err = read_line_filled_buffer(self)
    if err then
      return read_by_line(self)
    end

    return line, nil
  end

  -- no bytes in the buffer, let's read some
  if bufferLen == 0 then
    local line, err = read_line_zero_buffer(self)
    if err then
      return read_by_line(self)
    end

    return line, nil
  end
end

local function read_all(self)
  -- reads 'till close err is received
  repeat
    local msg, err = self.context:read(8192)
    if msg then
      self.readBuffer:put(msg)
    end

    if co_is_yieldable() then
      co_yield()
    end
  until err == "closed"

  return self.readBuffer:tostring(), nil
end

--- Receives `x` bytes or a line `*l` or the full buffer `*a` from the socket.
--- @param pattern? number|string Receives a line by default
--- @return string|nil message
--- @return string|nil err
function TLSSocket:receive(pattern)
  pattern = pattern or "*l"

  if type(pattern) == "number" then
    return read_by_length(self, pattern)
  end

  if pattern == "*l" then
    return read_by_line(self)
  end

  -- work in progress
  if pattern == "*a" then
    return read_all(self)
  end
end

return TLSSocket