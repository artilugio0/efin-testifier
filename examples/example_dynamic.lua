function test_dynamic()
  for i = 1,10 do
    register_test("dynamic_test_" .. tostring(i), function()
      print("running " .. tostring(i) .. "!!!")
      os.execute("sleep 3")
    end)
  end
end
