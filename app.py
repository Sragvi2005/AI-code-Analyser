from flask import Flask, render_template, request
from analyzer import analyze_code
import os
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = []
    code = ""

    if request.method == "POST":
        code = request.form["code"]
        result = analyze_code(code)

    return render_template("index.html", result=result, code=code)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)