import http from "k6/x/tlsauth/http";

const cert = open("client.crt");
const key = open("client.key");

export default function () {
  const res = http.get(__ENV.URL, {
    tlsAuth: { cert, key },
    tags: { name: "mtls" },
  });
  if (res.status !== 200) {
    throw new Error(`status=${res.status} error=${res.error}`);
  }
}
