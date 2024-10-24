from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        result = db.session.execute(db.select(User).where(User.email == request.form["email"]))
        user = result.scalar()

        if user:
            flash("You've already signed up with that email. Log in instead!")
            return redirect(url_for('login'))

        with app.app_context():
            new_user = User(
                name=request.form["name"],
                email=request.form["email"],
                password=generate_password_hash(request.form["password"], method='pbkdf2', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            return render_template("secrets.html", user=new_user)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))

        else:
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))

    return render_template('login.html')


@login_required
@app.route('/secrets')
def secrets():
    return render_template("secrets.html", user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@login_required
@app.route('/download')
def download():
    return send_from_directory('static', 'files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
