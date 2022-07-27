from flask import Flask, render_template, redirect, abort, url_for, flash, request, g
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, ForeignKey, Integer, Table
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, URL
from wtforms import StringField, SubmitField
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
ckeditor = CKEditor(app)
Bootstrap(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

##PARENT
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # list of BlogPost objects for each user
    # refers to "author" property in BlogPost class
    posts = relationship("BlogPost", back_populates="author")
    # Becoming Parent of Comments
    comments = relationship("Comment", back_populates="comment_author")

##CHILD
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key "users.id" refers to the tablename of User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, "posts" refers to post property
    # in User class
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    body = db.Column(db.Text, nullable=False)


db.create_all()


##WTF Form

class UserForm(FlaskForm):
    email = StringField("email", validators=[DataRequired()])
    password = StringField("password", validators=[DataRequired()])
    name = StringField("name", validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired()])
    password = StringField("password", validators=[DataRequired()])
    submit = SubmitField("Submit")


## Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = UserForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered, log in instead")
            return redirect(url_for('login'))

        new_user = User(
            email=request.form.get('email'),
            password=generate_password_hash(request.form.get('password'),
                                            method='pbkdf2:sha256',
                                            salt_length=8),
            name=request.form.get('name'),
        )

        ## Check if email already registered

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",
                           form=form,
                           current_user=current_user,
                           logged_in=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email
        if User.query.filter_by(email=email).first():
            user = User.query.filter_by(email=email).first()
        else:
            flash('Check your email, and try again')
            return redirect(url_for('login'))
        # Check stored hash
        if not user or not check_password_hash(user.password, password):
            flash('Check your password, and try again')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for("get_all_posts"))


    return render_template("login.html",
                           form=form,
                           logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        new_comment = Comment(
            author_id=current_user.id,
            post_id=post_id,
            body=form.body.data,
        )
        try:
            print(current_user.name)
        except AttributeError:
            flash("Login to comment")
            return redirect(url_for('login'))
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    # else:
    #     flash("Login to comment")
    #     return redirect(url_for('login'))
    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           form=form)


@app.route("/about")
def about():
    return render_template("about.html",
                           logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html",
                           logged_in=current_user.is_authenticated)

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html",
                           form=form,
                           current_user=current_user,
                           logged_in=True)



@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html",
                           form=edit_form,
                           logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
