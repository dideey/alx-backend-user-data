#!/usr/bin/env python3
"""Flask App 
"""
from flask import jsonify, app

@app.route('/', methods=['GET'], strict_slashes=False)

def hello():
    """GET / status
    """
    return jsonify({"message": "Bienvenue"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")