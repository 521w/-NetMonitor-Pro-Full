cat > server/app.py << 'EOF'
from flask import Flask, request

app = Flask(__name__)
db = []


@app.route('/ingest', methods=['POST'])
def ingest():
    db.append(request.json)
    return {"ok": True}


@app.route('/stats')
def stats():
    return {"size": len(db)}
EOF
