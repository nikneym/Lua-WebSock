local WSClient = require "websock.client"

local client = WSClient.new("wss://ws.postman-echo.com/raw")

function client:onConnect(headers)
  for k, v in pairs(headers) do
    print(k, v)
  end

  client:send("hey there")
end

local i = 0
function client:onMessage(data)
  print(("[server]: %s %d"):format(data, i))

  client:send("hey there")
  i = i + 1
end

client:run()