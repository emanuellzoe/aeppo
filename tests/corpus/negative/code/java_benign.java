class Tools {
    // Runtime.getRuntime().exec(cmd) in a comment
    String text = "Runtime.getRuntime().exec(cmd)";
    void run(String file) throws Exception {
        new ProcessBuilder("git", "log", file).start();
        Runtime.getRuntime().exec(new String[]{"git", "status"});
        pattern.exec(file);
    }
}
