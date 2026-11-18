# Never call os.system() here; see docs.
model.eval()
ssh.exec(command)
doc = "os.system(x)"
