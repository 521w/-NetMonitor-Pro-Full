from flask import Flask, request

app = Flask(__name__)
db = []


@app.route('/ingest', methods=['POST'])
def ingest():
    db.append(request.get_json(force=True))
    return {"ok": True}


@app.route('/stats')
def stats():
    return {"size": len(db)}
