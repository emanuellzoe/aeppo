// sentraio dogfood: a contract helper named exec, not a shell call
const exec = (action, approval = null) => agent.callRaw(vault, 'execute', { action, approval })
let r = await exec(pay(amount))
