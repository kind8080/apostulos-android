package apostulos.securityproxy.net

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.nio.charset.Charset
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** Proxy HTTP local. CONNECT cria túnel TCP; o conteúdo TLS permanece criptografado. */
class LocalHttpProxyServer(
    private val port: Int = 8888,
    private val onEvent: (String) -> Unit
) {
    private val running = AtomicBoolean(false)
    @Volatile private var server: ServerSocket? = null

    fun start(): Boolean {
        if (running.get()) return true
        return try {
            val socket = ServerSocket()
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 32)
            server = socket
            running.set(true)
            thread(name = "apostulos-proxy-accept") {
                while (running.get()) {
                    try {
                        val client = socket.accept()
                        thread(name = "apostulos-proxy-client") { handle(client) }
                    } catch (e: Exception) {
                        if (running.get()) onEvent("Erro ao aceitar conexão: ${e.message ?: e.javaClass.simpleName}")
                    }
                }
            }
            onEvent("Proxy iniciado em 127.0.0.1:$port")
            true
        } catch (e: Exception) {
            running.set(false)
            onEvent("Não foi possível iniciar o proxy: ${e.message ?: e.javaClass.simpleName}")
            false
        }
    }

    fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) { }
        server = null
        onEvent("Proxy parado")
    }

    fun isRunning(): Boolean = running.get()

    private fun handle(client: Socket) {
        client.use { incoming ->
            incoming.soTimeout = 20_000
            val input = BufferedInputStream(incoming.getInputStream())
            val output = BufferedOutputStream(incoming.getOutputStream())
            val requestLine = readLine(input) ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 3) return
            val method = parts[0].uppercase()
            val target = parts[1]
            val version = parts[2]
            val headers = mutableListOf<String>()
            var hostHeader: String? = null
            var contentLength = 0
            while (true) {
                val line = readLine(input) ?: break
                if (line.isEmpty()) break
                headers += line
                if (line.startsWith("Host:", true)) hostHeader = line.substringAfter(':').trim()
                if (line.startsWith("Content-Length:", true)) contentLength = line.substringAfter(':').trim().toIntOrNull() ?: 0
            }

            if (method == "CONNECT") {
                val host = target.substringBeforeLast(':', target).trim('[', ']')
                val remotePort = target.substringAfterLast(':', "443").toIntOrNull() ?: 443
                onEvent("CONNECT $host:$remotePort")
                Socket().use { remote ->
                    remote.connect(InetSocketAddress(host, remotePort), 10_000)
                    remote.soTimeout = 120_000
                    incoming.soTimeout = 120_000
                    output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    tunnel(incoming, input, output, remote)
                }
                return
            }

            val uri = try { URI(target) } catch (_: Exception) { null }
            val host = uri?.host ?: hostHeader?.substringBefore(':')
            val remotePort = uri?.port?.takeIf { it > 0 } ?: 80
            if (host.isNullOrBlank()) {
                output.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nHost ausente".toByteArray())
                output.flush()
                return
            }
            val path = (uri?.rawPath?.ifBlank { "/" } ?: target).let { p ->
                if (uri?.rawQuery != null) "$p?${uri.rawQuery}" else p
            }
            onEvent("CLEAR_HTTP $method $host${uri?.rawPath ?: "/"} [query omitida]")
            Socket().use { remote ->
                remote.connect(InetSocketAddress(host, remotePort), 10_000)
                remote.soTimeout = 30_000
                val remoteOut = BufferedOutputStream(remote.getOutputStream())
                remoteOut.write("$method $path $version\r\n".toByteArray(Charsets.US_ASCII))
                var hasHost = false
                headers.forEach { header ->
                    if (header.startsWith("Proxy-", true)) return@forEach
                    if (header.startsWith("Host:", true)) hasHost = true
                    remoteOut.write((header + "\r\n").toByteArray(Charsets.ISO_8859_1))
                }
                if (!hasHost) remoteOut.write("Host: $host\r\n".toByteArray(Charsets.US_ASCII))
                remoteOut.write("Connection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                val chunked = headers.any { it.startsWith("Transfer-Encoding:", true) && it.contains("chunked", true) }
                if (chunked) copyChunked(input, remoteOut)
                else if (contentLength in 1..(2 * 1024 * 1024)) copyExactly(input, remoteOut, contentLength)
                remoteOut.flush()
                remote.getInputStream().copyTo(output)
                output.flush()
            }
        }
    }

    private fun tunnel(client: Socket, clientIn: InputStream, clientOut: BufferedOutputStream, remote: Socket) {
        // Um lado encerrado encerra o túnel inteiro e libera a outra thread.
        val firstFinished = java.util.concurrent.CountDownLatch(1)
        thread(name = "apostulos-tunnel-up") {
            try {
                val out = remote.getOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = clientIn.read(buffer)
                    if (count < 0) break
                    out.write(buffer, 0, count)
                    out.flush()
                }
                remote.shutdownOutput()
            } catch (_: Exception) { }
            finally { firstFinished.countDown() }
        }
        thread(name = "apostulos-tunnel-down") {
            try {
                val input = remote.getInputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    clientOut.write(buffer, 0, count)
                    clientOut.flush()
                }
                client.shutdownOutput()
            } catch (_: Exception) { }
            finally { firstFinished.countDown() }
        }
        try { firstFinished.await(120, java.util.concurrent.TimeUnit.SECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        try { client.close() } catch (_: Exception) { }
        try { remote.close() } catch (_: Exception) { }
    }

    private fun readLine(input: InputStream, max: Int = 8192): String? {
        val out = ByteArrayOutputStream()
        while (out.size() < max) {
            val b = input.read()
            if (b == -1) return if (out.size() == 0) null else out.toString("ISO-8859-1").trimEnd('\r')
            if (b == 10) return out.toString("ISO-8859-1").trimEnd('\r')
            out.write(b)
        }
        throw IllegalArgumentException("Linha HTTP excede o limite")
    }

    private fun copyExactly(input: InputStream, output: BufferedOutputStream, count: Int) {
        var remaining = count
        val buffer = ByteArray(8192)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) break
            output.write(buffer, 0, read)
            remaining -= read
        }
    }

    private fun copyChunked(input: InputStream, output: BufferedOutputStream) {
        repeat(10_000) {
            val line = readLine(input) ?: return
            output.write((line + "\r\n").toByteArray(Charsets.US_ASCII))
            val size = line.substringBefore(';').trim().toLongOrNull(16) ?: return
            if (size == 0L) {
                while (true) {
                    val trailer = readLine(input) ?: break
                    output.write((trailer + "\r\n").toByteArray(Charsets.ISO_8859_1))
                    if (trailer.isEmpty()) break
                }
                return
            }
            if (size > 2L * 1024 * 1024) return
            copyExactly(input, output, size.toInt())
            val cr = input.read()
            val lf = input.read()
            if (cr >= 0) output.write(cr)
            if (lf >= 0) output.write(lf)
        }
    }
}
