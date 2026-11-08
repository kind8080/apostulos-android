package apostulos.securityproxy

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** HTTP forward proxy restricted to loopback; CONNECT tunnels are supported. */
class LocalHttpProxyServer(
    private val port: Int,
    private val onState: (Boolean) -> Unit
) {
    private val running = AtomicBoolean(false)
    private val clients = Executors.newCachedThreadPool()
    @Volatile private var serverSocket: ServerSocket? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        clients.execute {
            try {
                serverSocket = ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"))
                onState(true)
                while (running.get()) {
                    val client = serverSocket?.accept() ?: break
                    clients.execute { handle(client) }
                }
            } catch (_: SocketException) {
                // Expected when stop() closes the listening socket.
            } catch (_: Exception) {
                onState(false)
            } finally {
                running.set(false)
                onState(false)
            }
        }
    }

    fun stop() {
        running.set(false)
        try { serverSocket?.close() } catch (_: Exception) { }
        serverSocket = null
        clients.shutdownNow()
        onState(false)
    }

    private fun handle(client: Socket) {
        client.use { incoming ->
            incoming.soTimeout = 30_000
            val input = BufferedInputStream(incoming.getInputStream())
            val output = BufferedOutputStream(incoming.getOutputStream())
            val header = readHeader(input) ?: return
            val lines = header.split("\r\n")
            val request = lines.firstOrNull()?.split(" ") ?: return
            if (request.size < 3) return badRequest(output)
            val method = request[0].uppercase()
            if (method == "CONNECT") {
                val target = parseHostPort(request[1], 443) ?: return badRequest(output)
                if (target.second !in setOf(443, 8443)) return forbidden(output)
                Socket(target.first, target.second).use { remote ->
                    output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    relay(input, remote.getOutputStream(), remote.getInputStream(), output)
                }
            } else {
                val uri = try { java.net.URI(request[1]) } catch (_: Exception) { return badRequest(output) }
                if (uri.scheme != "http" || uri.host.isNullOrBlank()) return forbidden(output)
                val port = if (uri.port > 0) uri.port else 80
                if (port != 80 && port != 8080) return forbidden(output)
                Socket(uri.host, port).use { remote ->
                    val path = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") +
                        (uri.rawQuery?.let { "?$it" } ?: "")
                    val rewritten = buildString {
                        append(method).append(' ').append(path).append(' ').append(request[2]).append("\r\n")
                        lines.drop(1).filter { it.isNotBlank() && !it.startsWith("Proxy-Connection:", true) }
                            .forEach { append(it).append("\r\n") }
                        append("Connection: close\r\n\r\n")
                    }
                    val remoteOut = BufferedOutputStream(remote.getOutputStream())
                    if (lines.any { it.startsWith("Transfer-Encoding:", true) }) return notImplemented(output)
                    val contentLength = lines.firstOrNull { it.startsWith("Content-Length:", true) }
                        ?.substringAfter(':')?.trim()?.toLongOrNull() ?: 0L
                    if (contentLength < 0 || contentLength > 20L * 1024 * 1024) return badRequest(output)
                    remoteOut.write(rewritten.toByteArray(Charsets.ISO_8859_1))
                    copyExactly(input, remoteOut, contentLength)
                    remoteOut.flush()
                    remote.getInputStream().copyTo(output)
                    output.flush()
                }
            }
        }
    }

    private fun readHeader(input: BufferedInputStream): String? {
        val bytes = ArrayList<Byte>(4096)
        var state = 0
        while (bytes.size < 32 * 1024) {
            val value = input.read()
            if (value < 0) return null
            bytes.add(value.toByte())
            state = when {
                state == 0 && value == 13 -> 1
                state == 1 && value == 10 -> 2
                state == 2 && value == 13 -> 3
                state == 3 && value == 10 -> 4
                value == 13 -> 1
                else -> 0
            }
            if (state == 4) return bytes.toByteArray().toString(Charsets.ISO_8859_1)
        }
        return null
    }

    private fun parseHostPort(value: String, defaultPort: Int): Pair<String, Int>? = try {
        val host = value.substringBeforeLast(':', value).removePrefix("[").removeSuffix("]")
        val port = value.substringAfterLast(':', "").toIntOrNull() ?: defaultPort
        if (host.isBlank() || port !in 1..65535) null else host to port
    } catch (_: Exception) { null }

    private fun relay(clientIn: BufferedInputStream, remoteOutRaw: java.io.OutputStream,
                      remoteInRaw: java.io.InputStream, clientOut: BufferedOutputStream) {
        val remoteOut = BufferedOutputStream(remoteOutRaw)
        val upstream = Thread { try { clientIn.copyTo(remoteOut); remoteOut.flush() } catch (_: Exception) { } }
        upstream.start()
        try { remoteInRaw.copyTo(clientOut); clientOut.flush() } catch (_: Exception) { }
        try { upstream.join(2_000) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
    }

    private fun copyExactly(input: java.io.InputStream, output: java.io.OutputStream, length: Long) {
        var remaining = length
        val buffer = ByteArray(8192)
        while (remaining > 0) {
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (count < 0) throw java.io.EOFException("Request body ended early")
            output.write(buffer, 0, count)
            remaining -= count
        }
    }

    private fun badRequest(out: BufferedOutputStream) = respond(out, "400 Bad Request")
    private fun forbidden(out: BufferedOutputStream) = respond(out, "403 Forbidden")
    private fun notImplemented(out: BufferedOutputStream) = respond(out, "501 Not Implemented")
    private fun respond(out: BufferedOutputStream, status: String) {
        try { out.write("HTTP/1.1 $status\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".toByteArray()); out.flush() } catch (_: Exception) { }
    }
}
