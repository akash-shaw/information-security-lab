import os
import json
import base64
import uuid
from datetime import datetime, timezone

from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Random import random, get_random_bytes
from Crypto.Util.number import GCD, inverse

try:
    from phe import paillier
except ImportError:
    print("Install dependency: pip install phe")
    raise

STATE_FILE = "server_state.json"
INPUT_DIR = "inputdata"


def ensure_dirs():
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"server": {}, "doctors": {}, "reports": [], "expenses": {}}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def gen_server_keys(state):
    if "rsa_oaep" in state["server"]:
        print("Server keys already exist.")
        return
    rsa_oaep_key = RSA.generate(1024)
    pub_pem = rsa_oaep_key.publickey().export_key().decode()
    priv_pem = rsa_oaep_key.export_key().decode()

    homo_rsa = RSA.generate(1024)
    n = int(homo_rsa.n)
    e = int(homo_rsa.e)
    d = int(homo_rsa.d)
    # base for exponent-trick homomorphic addition
    while True:
        base = random.randint(2, n - 2)
        if GCD(base, n) == 1:
            break
    max_exp = 10000

    pub, priv = paillier.generate_paillier_keypair(n_length=1024)

    state["server"]["rsa_oaep"] = {"pub_pem": pub_pem, "priv_pem": priv_pem}
    state["server"]["homo_rsa"] = {
        "n": n,
        "e": e,
        "d": d,
        "base": base,
        "max_exp": max_exp,
    }
    state["server"]["paillier"] = {"n": pub.n, "p": priv.p, "q": priv.q}
    save_state(state)
    print("Server RSA-OAEP, Homo-RSA, and Paillier keys generated.")


def get_paillier_keys(state):
    n = state["server"]["paillier"]["n"]
    p = state["server"]["paillier"]["p"]
    q = state["server"]["paillier"]["q"]
    pub = paillier.PaillierPublicKey(n)
    priv = paillier.PaillierPrivateKey(pub, p, q)
    return pub, priv


def register_doctor(state):
    name = input("Doctor name: ").strip()
    dept = input("Department: ").strip()
    doc_id = "doc_" + uuid.uuid4().hex[:8]

    eg_key = ElGamal.generate(1024, get_random_bytes)
    # ElGamal object has p,g,y,x attributes
    p = int(eg_key.p)
    g = int(eg_key.g)
    y = int(eg_key.y)
    x = int(eg_key.x)

    # Paillier encrypt department hash
    pub, _ = get_paillier_keys(state)
    dept_md5_int = int.from_bytes(MD5.new(dept.encode()).digest(), "big")
    dept_enc = pub.encrypt(dept_md5_int)

    state["doctors"][doc_id] = {
        "name": name,
        "department": dept,
        "department_md5": dept_md5_int,
        "department_paillier": {
            "ciphertext": int(dept_enc.ciphertext()),
            "exponent": dept_enc.exponent,
        },
        "elgamal": {"p": p, "g": g, "y": y, "x": x},
    }
    save_state(state)
    print(f"Registered doctor {name} with id {doc_id} in dept {dept}.")
    print(
        f"ElGamal pub (p,g,y) set. Department stored both plaintext and Paillier-encrypted."
    )


def list_markdown_files():
    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(".md")]
    for i, f in enumerate(files, 1):
        print(f"{i}. {f}")
    return files


def rsa_oaep_encrypt_large(data_bytes, pub_pem):
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub)  # SHA1 by default
    k = pub.size_in_bytes()
    hlen = 20
    max_pt = k - 2 * hlen - 2
    out = b""
    for i in range(0, len(data_bytes), max_pt):
        block = data_bytes[i : i + max_pt]
        out += cipher.encrypt(block)
    return base64.b64encode(out).decode()


def rsa_oaep_decrypt_large(b64, priv_pem):
    data = base64.b64decode(b64.encode())
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv)
    k = priv.size_in_bytes()
    out = b""
    for i in range(0, len(data), k):
        block = data[i : i + k]
        out += cipher.decrypt(block)
    return out


def elgamal_sign(doc_eg, msg_bytes):
    p = int(doc_eg["p"])
    g = int(doc_eg["g"])
    x = int(doc_eg["x"])
    H = int(MD5.new(msg_bytes).hexdigest(), 16) % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    kinv = inverse(k, p - 1)
    s = (kinv * (H - x * r)) % (p - 1)
    return int(r), int(s)


def elgamal_verify(pub_eg, msg_bytes, sig):
    p = int(pub_eg["p"])
    g = int(pub_eg["g"])
    y = int(pub_eg["y"])
    r, s = sig
    if not (1 < r < p):
        return False
    H = int(MD5.new(msg_bytes).hexdigest(), 16) % (p - 1)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, H, p)
    return v1 == v2


def doctor_submit_report(state):
    if not state["doctors"]:
        print("No doctors. Register first.")
        return
    doc_id = input("Enter your doctor id: ").strip()
    if doc_id not in state["doctors"]:
        print("Unknown doctor.")
        return
    files = list_markdown_files()
    if not files:
        print("Place a markdown file in inputdata/")
        return
    idx = int(input("Select file #: ").strip())
    filename = files[idx - 1]
    path = os.path.join(INPUT_DIR, filename)
    with open(path, "rb") as f:
        report_bytes = f.read()
    md5_hex = MD5.new(report_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()

    msg_to_sign = report_bytes + ts.encode()
    r, s = elgamal_sign(state["doctors"][doc_id]["elgamal"], msg_to_sign)

    pub_pem = state["server"]["rsa_oaep"]["pub_pem"]
    ct_b64 = rsa_oaep_encrypt_large(report_bytes, pub_pem)

    rep_id = "rep_" + uuid.uuid4().hex[:8]
    rec = {
        "report_id": rep_id,
        "doctor_id": doc_id,
        "doctor_name": state["doctors"][doc_id]["name"],
        "filename": filename,
        "timestamp_utc": ts,
        "md5_hex": md5_hex,
        "elgamal_sig": {"r": r, "s": s},
        "rsa_oaep_b64": ct_b64,
    }
    state["reports"].append(rec)
    save_state(state)
    print("Report submitted.")
    print(f"id: {rep_id}")
    print(f"md5: {md5_hex}")
    print(f"sig: r={r} s={s}")
    print(f"enc blocks (base64 len): {len(ct_b64)}")


def homo_rsa_encrypt_amount(state, amount):
    n = int(state["server"]["homo_rsa"]["n"])
    e = int(state["server"]["homo_rsa"]["e"])
    base = int(state["server"]["homo_rsa"]["base"])
    max_exp = int(state["server"]["homo_rsa"]["max_exp"])
    if amount < 0 or amount > max_exp:
        raise ValueError("amount out of allowed range")
    m = pow(base, amount, n)
    c = pow(m, e, n)
    return int(c)


def homo_rsa_discrete_log(m, base, mod, max_k):
    val = 1 % mod
    if m == 1 % mod:
        return 0
    for k in range(1, max_k + 1):
        val = (val * base) % mod
        if val == m:
            return k
    return None


def doctor_submit_expense(state):
    if not state["doctors"]:
        print("No doctors. Register first.")
        return
    doc_id = input("Enter your doctor id: ").strip()
    if doc_id not in state["doctors"]:
        print("Unknown doctor.")
        return
    amt = int(input("Expense integer (<=10000): ").strip())
    c = homo_rsa_encrypt_amount(state, amt)
    state["expenses"].setdefault(doc_id, []).append(c)
    save_state(state)
    print(f"Encrypted expense stored for {doc_id}.")
    print(f"ciphertext: {c}")


def auditor_list_reports(state):
    if not state["reports"]:
        print("No reports.")
        return
    for r in state["reports"]:
        print(
            f"{r['report_id']} by {r['doctor_id']} at {r['timestamp_utc']} file={r['filename']} md5={r['md5_hex']}"
        )


def auditor_verify_report(state):
    if not state["reports"]:
        print("No reports.")
        return
    rep_id = input("Report id: ").strip()
    rec = next((r for r in state["reports"] if r["report_id"] == rep_id), None)
    if not rec:
        print("Not found.")
        return
    priv_pem = state["server"]["rsa_oaep"]["priv_pem"]
    pt = rsa_oaep_decrypt_large(rec["rsa_oaep_b64"], priv_pem)
    md5_calc = MD5.new(pt).hexdigest()
    ok_md5 = md5_calc == rec["md5_hex"]

    doc = state["doctors"][rec["doctor_id"]]
    pub_eg = {
        "p": doc["elgamal"]["p"],
        "g": doc["elgamal"]["g"],
        "y": doc["elgamal"]["y"],
    }
    msg = pt + rec["timestamp_utc"].encode()
    ok_sig = elgamal_verify(
        pub_eg, msg, (rec["elgamal_sig"]["r"], rec["elgamal_sig"]["s"])
    )

    ts = datetime.fromisoformat(rec["timestamp_utc"])
    now = datetime.now(timezone.utc)
    skew_sec = (now - ts).total_seconds()

    print("Verification results:")
    print(f"md5 match: {ok_md5}")
    print(f"signature valid: {ok_sig}")
    print(f"timestamp: {rec['timestamp_utc']}")
    print(f"server now: {now.isoformat()}")
    print(f"age seconds: {int(skew_sec)} (future? {skew_sec < 0})")


def auditor_keyword_search(state):
    if not state["doctors"]:
        print("No doctors.")
        return
    dept_q = input("Search department: ").strip()
    pub, priv = get_paillier_keys(state)
    q_int = int.from_bytes(MD5.new(dept_q.encode()).digest(), "big")
    q_enc = pub.encrypt(q_int)

    print("Records:")
    found = []
    for doc_id, doc in state["doctors"].items():
        enc_info = doc["department_paillier"]
        enc_doc = paillier.EncryptedNumber(
            pub, int(enc_info["ciphertext"]), int(enc_info["exponent"])
        )
        diff = enc_doc - q_enc
        val = priv.decrypt(diff)
        is_match = val == 0
        if is_match:
            found.append(doc_id)
        print(
            f"{doc_id}: dept='{doc['department']}' enc_ct={enc_info['ciphertext']} match={is_match}"
        )
    print(f"Matches: {found}")


def auditor_sum_expenses(state):
    homo = state["server"]["homo_rsa"]
    n = int(homo["n"])
    d = int(homo["d"])
    base = int(homo["base"])
    max_exp = int(homo["max_exp"])
    if not state["expenses"]:
        print("No expenses.")
        return
    choice = input("Sum for 'all' or specific doc_id: ").strip()
    c_list = []
    if choice.lower() == "all":
        for doc_id, lst in state["expenses"].items():
            c_list += lst
    else:
        if choice not in state["expenses"]:
            print("No expenses for given id.")
            return
        c_list = state["expenses"][choice]
    if not c_list:
        print("No expenses to sum.")
        return
    prod = 1
    for c in c_list:
        prod = (prod * int(c)) % n
    m = pow(prod, d, n)
    s = homo_rsa_discrete_log(m, base, n, max_exp)
    print("Homomorphic sum result:")
    print(f"combined ciphertext (mod n): {prod}")
    if s is None:
        print("decrypted sum: could not recover (out of range)")
    else:
        print(f"decrypted sum: {s}")


def list_doctors(state):
    if not state["doctors"]:
        print("No doctors.")
        return
    for doc_id, d in state["doctors"].items():
        print(f"{doc_id}: {d['name']} dept='{d['department']}'")


def doctor_list_my_data(state):
    doc_id = input("Enter your doctor id: ").strip()
    if doc_id not in state["doctors"]:
        print("Unknown doctor.")
        return
    print("Reports:")
    for r in state["reports"]:
        if r["doctor_id"] == doc_id:
            print(f"{r['report_id']} {r['filename']} {r['timestamp_utc']}")
    print("Expenses (ciphertexts):")
    for c in state["expenses"].get(doc_id, []):
        print(c)


def main():
    ensure_dirs()
    state = load_state()
    while True:
        print("\nMain Menu")
        print("1. Setup server keys")
        print("2. Register doctor")
        print("3. Doctor menu")
        print("4. Auditor menu")
        print("5. List doctors")
        print("0. Exit")
        ch = input("Choice: ").strip()
        if ch == "1":
            gen_server_keys(state)
        elif ch == "2":
            if "rsa_oaep" not in state["server"]:
                print("Setup server keys first.")
            else:
                register_doctor(state)
        elif ch == "3":
            while True:
                print("\nDoctor Menu")
                print("1. Submit report (md file in inputdata/)")
                print("2. Submit expense (homomorphic RSA)")
                print("3. List my reports/expenses")
                print("0. Back")
                dch = input("Choice: ").strip()
                if dch == "1":
                    if "rsa_oaep" not in state["server"]:
                        print("Setup server keys first.")
                    else:
                        doctor_submit_report(state)
                elif dch == "2":
                    if "homo_rsa" not in state["server"]:
                        print("Setup server keys first.")
                    else:
                        doctor_submit_expense(state)
                elif dch == "3":
                    doctor_list_my_data(state)
                elif dch == "0":
                    break
                else:
                    print("Invalid.")
        elif ch == "4":
            while True:
                print("\nAuditor Menu")
                print("1. List reports")
                print("2. Verify a report (sig + timestamp)")
                print("3. Dept keyword search (Paillier)")
                print("4. Sum expenses (homomorphic RSA)")
                print("0. Back")
                ach = input("Choice: ").strip()
                if ach == "1":
                    auditor_list_reports(state)
                elif ach == "2":
                    auditor_verify_report(state)
                elif ach == "3":
                    if "paillier" not in state["server"]:
                        print("Setup server keys first.")
                    else:
                        auditor_keyword_search(state)
                elif ach == "4":
                    if "homo_rsa" not in state["server"]:
                        print("Setup server keys first.")
                    else:
                        auditor_sum_expenses(state)
                elif ach == "0":
                    break
                else:
                    print("Invalid.")
        elif ch == "5":
            list_doctors(state)
        elif ch == "0":
            print("Bye.")
            break
        else:
            print("Invalid.")


if __name__ == "__main__":
    main()
