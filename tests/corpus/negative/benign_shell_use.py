import subprocess, pty

subprocess.run(["bash", "build.sh"])
subprocess.run(["bash", "-n", path])
subprocess.run(["sh", "-c", "command -v git"])
subprocess.run(["git", "-c", key, "status"])
pty.spawn(["systemctl", "--user", "restart", "app"])
