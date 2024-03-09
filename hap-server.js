const net = require("net")
const crypto = require("crypto");
const { log } = require("console");

const Handler = ({
    send,
    close,
    onmsg,
    socket
}) => false

function createServer(port, handler = Handler) {
    net.createServer(socket => {

        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });

        var clientPublicKey = false

        socket.write(`handshake hap 1.0\n${publicKey.export({ type: "pkcs1", format: "pem" }).toString("ascii")}`)

        socket.on("data", chunk => {

            const data = chunk.toString("utf-8")

            if (!clientPublicKey) {

                const lines = data.split("\n")

                if (lines[0] == "handshake hap 1.0") {

                    clientPublicKey = lines.slice(1, lines.length).join("\n")

                    handler({
                        send: (data) => {

                            socket.write(crypto.publicEncrypt(clientPublicKey, data))

                        },
                        close: c => socket.destroy(c),
                        onmsg: listener => socket.on("data", chunk => {

                            listener(crypto.privateDecrypt(privateKey, chunk))

                        }),
                        socket
                    })

                }

                else socket.destroy(11)

            }

        })

    }).listen(port)
}

createServer(2112, ({ send, onmsg }) => {

    send(Buffer.from("Hello World from server"))

    onmsg(data => {
        log(data.toString("utf-8"))
    })

})

process.on("uncaughtException", err => log(err))