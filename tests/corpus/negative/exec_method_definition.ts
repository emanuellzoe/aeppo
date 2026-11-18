class Client {
  async exec(command: string) {
    return this.send(command)
  }
}
