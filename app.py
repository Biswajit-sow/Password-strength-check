from flask import Flask, render_template, request, render_template, request
from Password_strength_checker import evaluate_password, generate_suggestive_password, provide_improvement_tips

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    feedback = None
    suggest_password = None
    password_score = None

    if request.method == 'POST':
        password = request.form.get('password')
        is_valid, strength, score, feedback_list = evaluate_password(password)
        password_score = f"{strength} ({score}/100)"
        
        if not is_valid:
            suggest_password = generate_suggestive_password()

        return render_template('index.html', feedback=feedback_list, score=password_score, suggest_password=suggest_password)

    return render_template('index.html', feedback=feedback, score=password_score, suggest_password=suggest_password)

if __name__ == '__main__':
    app.run(debug=True)
