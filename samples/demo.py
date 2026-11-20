# ShieldLocal demo file – intentionally vulnerable.
import hashlib, pickle, subprocess, yaml, requests
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "hunter2hunter2"

@app.route("/run")
def run():
    subprocess.run(request.args["cmd"], shell=True)
    cfg = yaml.load(request.data)
    obj = pickle.loads(request.data)
    cur.execute(f"SELECT * FROM users WHERE name = '{request.args['n']}'")
    return hashlib.md5(request.data).hexdigest()

requests.get("https://internal.local", verify=False)
app.run(debug=True)
