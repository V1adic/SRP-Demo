const N = bigInt("167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939");
const g = bigInt(2);

function generateRandomBigInt(bits) {
    const byteLength = Math.ceil(bits / 8);
    const randomBytes = new Uint8Array(byteLength);
    crypto.getRandomValues(randomBytes);
    return bigInt.fromArray([...randomBytes], 256);
}

function combineBytes(...args) {
    return args.join("");
}

function computeSha256(bytes) {
    const hashHex = sha256(bytes);
    return bigInt(hashHex, 16);
}

class SrpClient {
    constructor(password) {
        this.password = password;
        this.a = generateRandomBigInt(256);
    }

    generatePublicKey() {
        this.A = g.modPow(this.a, N);
        return this.A;
    }

    computeSessionKey(B, salt) {
        this.salt = bigInt(salt);
        const x = computeSha256(this.salt.toString() + this.password);
        const u = computeSha256(combineBytes(this.A.toString(), B.toString()));
        const k = computeSha256(combineBytes(N.toString(), g.toString()));

        const gX = g.modPow(x, N);
        const kTimesGX = k.times(gX).mod(N);
        const base = (B.plus(N).minus(kTimesGX)).mod(N);

        const exponent = this.a.plus(u.times(x));
        this.S = base.modPow(exponent, N);
        if (this.S.lesser(0)) {
            this.S = this.S.plus(N);
        }
        this.K = computeSha256(this.S.toString());
        return this.K;
    }

    computeClientProof(B) {
        return computeSha256(combineBytes(this.A.toString(), B.toString(), this.K.toString()));
    }

    verifyServerProof(M1, M2) {
        const computedM2 = computeSha256(combineBytes(this.A.toString(), M1.toString(), this.K.toString()));
        return computedM2.eq(M2);
    }
}

async function register() {
    const username = document.getElementById("registerUsername").value;
    const password = document.getElementById("registerPassword").value;
    const client = new SrpClient(password);
    client.salt = generateRandomBigInt(128);
    const x = computeSha256(client.salt.toString() + password);
    const v = g.modPow(x, N);

    const response = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, salt: client.salt.toString(), verifier: v.toString() })
    });
    const text = await response.text();
    const resultElement = document.getElementById("registerResult");
    if (response.ok) {
        resultElement.innerText = "Registration successful!";
        resultElement.style.color = "#28a745"; // Зеленый цвет для успеха
    } else {
        const errorData = JSON.parse(text);
        resultElement.innerText = errorData.message || "Registration failed!";
        resultElement.style.color = "#dc3545"; // Красный цвет для ошибки
    }
}

async function login() {
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;
    const client = new SrpClient(password);
    const A = client.generatePublicKey();

    const startResponse = await fetch("/api/login/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, A: A.toString() })
    });
    const startText = await startResponse.text();
    if (!startResponse.ok) {
        document.getElementById("loginResult").innerText = JSON.parse(startText).message || "Login failed!";
        document.getElementById("loginResult").style.color = "#dc3545";
        return;
    }
    const startData = JSON.parse(startText);
    const B = bigInt(startData.b);
    const salt = startData.salt;
    client.computeSessionKey(B, salt);
    const M1 = client.computeClientProof(B);

    const verifyResponse = await fetch("/api/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, M1: A.toString() + "|" + M1.toString() })
    });
    const verifyText = await verifyResponse.text();
    if (!verifyResponse.ok) {
        document.getElementById("loginResult").innerText = JSON.parse(verifyText).message || "Login failed!";
        document.getElementById("loginResult").style.color = "#dc3545";
        return;
    }
    const verifyData = JSON.parse(verifyText);
    const M2 = bigInt(verifyData.m2);
    if (client.verifyServerProof(M1, M2)) {
        document.getElementById("loginResult").innerText = "Login successful!";
        document.getElementById("loginResult").style.color = "#28a745";
    } else {
        document.getElementById("loginResult").innerText = "Server proof verification failed!";
        document.getElementById("loginResult").style.color = "#dc3545";
    }
}