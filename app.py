from flask import Flask, render_template, request
from analyzer import analyze_code


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = []
    code = ""
    risk_score = 0
    risk_level = "low"

    if request.method == "POST":
        code = request.form["code"]
        result = analyze_code(code)
        
        
        # Calculate risk score
        for issue in result:
            if issue["severity"] == "HIGH":
                risk_score += 3
            elif issue["severity"] == "MEDIUM":
                risk_score += 2
            else:
                risk_score += 1

        risk_score = min(risk_score, 10)

        # Determine risk level
        if risk_score > 7:
            risk_level = "high"
        elif risk_score > 4:
            risk_level = "medium"

    return render_template(
        "index.html",
        result=result,
        code=code,
        risk_score=risk_score,
        risk_level=risk_level
    )

if __name__ == "__main__":
    app.run(debug=True)
