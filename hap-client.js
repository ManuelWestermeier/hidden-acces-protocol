const { log } = require("console");
const crypto = require("crypto")
const net = require("net")

const Handler = ({
    send,
    close,
    onmsg,
    socket
}) => false

async function createConection(options, handler = Handler) {

    const socket = net.createConnection(options)

    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
    });

    var serverPublicKey = false

    socket.write(`handshake hap 1.0\n${publicKey.export({ type: "pkcs1", format: "pem" }).toString("ascii")}`)

    socket.on("data", chunk => {

        const data = chunk.toString("utf-8")

        if (!serverPublicKey) {

            const lines = data.split("\n")

            if (lines[0] == "handshake hap 1.0") {

                serverPublicKey = lines.slice(1, lines.length).join("\n")

                handler({
                    send: (data) => {

                        socket.write(crypto.publicEncrypt(serverPublicKey, data))

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

}

createConection({ port: 2112, host: "localhost" }, ({ send, onmsg }) => {

    send(Buffer.from("Hello World from client"))

    onmsg(data => {
        log(data.toString("utf-8"))
    })

})