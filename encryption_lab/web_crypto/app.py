from flask import Flask, render_template, request, jsonify
from encryption_platform import EncryptionPlatform

app = Flask(__name__)
platform = EncryptionPlatform()

# 存储当前会话的 key 对
session_keys = {
    'algo': None,
    'pub': None,
    'priv': None,
    'last_ct': None
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/gen_keys", methods=["POST"])
def gen_keys():
    algo = request.json.get("algo")
    pub, priv = platform.generate_keys(algo)
    session_keys.update(algo=algo, pub=pub, priv=priv, last_ct=None)
    return jsonify({
        "pub": repr(pub),
        "priv": repr(priv)
    })

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json
    algo = session_keys['algo']
    pub = session_keys['pub']
    msg = data.get("plain").strip()
    if algo in ["RSA","ElGamal"]:
        try:
            msg = int(msg)
        except:
            return jsonify({"error": "RSA/ElGamal 明文必须为整数"}), 400

    if algo == "ElGamal":
        c1, c2 = platform.encrypt(algo, msg, pub)
        ct = f"({c1},{c2})"
    else:
        ct = str(platform.encrypt(algo, msg, pub))

    session_keys['last_ct'] = ct
    return jsonify({"ct": ct})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.json
    algo = session_keys['algo']
    priv = session_keys['priv']
    pub = session_keys['pub']
    inp = data.get("cipher", "").strip()
    ct_str = inp or session_keys.get('last_ct') or ""
    if not ct_str:
        return jsonify({"error": "没有可解密的密文"}), 400

    try:
        if algo == "RSA":
            pt = platform.decrypt(algo, int(ct_str), priv)
        elif algo == "ElGamal":
            clean = ct_str.replace("，",",").replace("（","(").replace("）",")").strip()
            if clean.startswith("(") and clean.endswith(")"):
                clean = clean[1:-1]
            if "," not in clean:
                raise ValueError
            a,b = clean.split(",",1)
            pt = platform.decrypt(algo, (int(a), int(b)), priv, pub)
        else:  # ECC
            pt = platform.decrypt(algo, ct_str, priv)
        return jsonify({"pt": str(pt)})
    except Exception:
        return jsonify({"error": "解密失败，格式或密钥不匹配"}), 400

if __name__ == "__main__":
    app.run(debug=True)
