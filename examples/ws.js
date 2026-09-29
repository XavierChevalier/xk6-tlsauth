import ws from "k6/x/tlsauth/ws";

const cert = open("client.crt");
const key = open("client.key");

export default function () {
  const res = ws.connect(
    __ENV.WSS_URL,
    {
      tlsAuth: { cert, key },
    },
    function (socket) {
      socket.on("open", function () {
        socket.send("ping");
        socket.close();
      });
    },
  );
  if (res.status !== 101) {
    throw new Error("upgrade failed: " + res.status);
  }
}
