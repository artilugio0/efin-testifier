function preconditions()
  error("this should not be executed")
end

request = {
    method = "GET",
    url = "https://www.google.com",
    headers = {
        ["User-Agent"] = "Golang-Lua-Client/1.0",
        ["Accept"] = "text/html",
    },
}
