class Loader
  def load(blob, code)
    eval(code)
    Marshal.load(blob)
    instance = eval params[:expr]
  end
end
