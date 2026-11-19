# system("rm -rf #{dir}") in a comment
class Runner
  def exec(job)
    job.call
  end

  def run(ref)
    system("git", "log", ref)
    system("make test")
    `git rev-parse HEAD`
    @runner.exec(ref)
    obj.system(ref)
    msg = "eval(#{ref})"
    YAML.safe_load(ref)
  end
end
=begin
eval(params[:x])
=end
