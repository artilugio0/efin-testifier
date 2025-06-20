function preconditions()
  local context = {
    counter = 0,
    request = {
        method = "GET",
        url = "https://www.google.com",
        headers = {
            ["User-Agent"] = "Lua-Test/1.0"
        }
    }
  }

  return context
end

