from typing import Optional
from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_paginate import Pagination, get_page_parameter
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime
from flask_login import UserMixin
from werkzeug.utils import secure_filename
import os
from flask_wtf.csrf import CSRFProtect
basedir = os.path.abspath(os.path.dirname(__file__))
# ==== CONFIGURATION ====
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
csrf = CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'blog.db')
app.config['UPLOAD_FOLDER'] = 'static/uploads'


# Create image upload folder if not exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==== USER LOADER ====
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==== USER MODEL ====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(10))  # admin, author, reader
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    profile_image = db.Column(db.String(200))  

# ==== POST MODEL ====
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    image = db.Column(db.String(100))
    category = db.Column(db.String(100))
    tags = db.Column(db.String(200))
    status = db.Column(db.String(50), default='Draft')  # Draft, Published, Pending, Rejected
    scheduled_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comments = db.relationship('Comment', backref='post', lazy=True)
    

# ==== COMMENT MODEL ====
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    children = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_reported = db.Column(db.Boolean, default=False)
# ==== NOTIFICATION MODEL ====

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)

# ==== TAG MODEL ====
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)

# ==== FORMS ====
class RegisterForm(FlaskForm):
   name = StringField('Name', validators=[DataRequired(), Length(min=4, max=20)])
   email = StringField('Email', validators=[DataRequired(), Email()])
   password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
   confirm = PasswordField("Confirm Password", validators=[EqualTo('password')])
   role = SelectField("Role", choices=[('reader', 'Reader'), ('author', 'Author') , ('admin', 'Admin')])
   submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = CKEditorField("Content", validators=[DataRequired()])
    image = FileField("Upload Image")
    category = SelectField("Category", coerce=int, validators=[DataRequired()])
    tags = StringField("Tags (comma-separated)", validators=[DataRequired()])
    status = SelectField("Status", choices=[("Draft", "Draft"), ("Pending", "Pending Review"), ("Published", "Publish Now"), ("Rejected", "Rejected")])
    scheduled_time = StringField("Schedule (yyyy-mm-dd hh:mm) — optional")
    submit = SubmitField("Create Post")

class CommentForm(FlaskForm):
    content = TextAreaField("Comment", validators=[DataRequired()])
    parent_id = StringField()  # hidden field
    submit = SubmitField("Post Comment")

class CategoryForm(FlaskForm):
    name = StringField("Category Name", validators=[DataRequired()])
    submit = SubmitField("Save")


class TagForm(FlaskForm):
    name = StringField("Tag Name", validators=[DataRequired()])
    submit = SubmitField("Save") 
#---------profile--------
class ProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    profile_image = FileField("Profile Image", validators=[FileAllowed(['jpg', 'png', 'jpeg'])])  # ✅ Added
    current_password = PasswordField("Current Password")
    new_password = PasswordField("New Password", validators=[Length(min=6)])
    confirm_password = PasswordField("Confirm New Password", validators=[EqualTo('new_password', message="Passwords must match")])
    submit = SubmitField("Update Profile")


# ==== ROUTES ====
@app.route('/')
@app.route('/')
def home():
    publish_scheduled_posts()

    # Show NO published posts on home
    posts = []  # send empty list to hide all posts from home page

    return render_template('home.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already exists!", "danger")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Logged in successfully.", "success")

            # ✅ Fix: Reader role redirect
            if user.role == 'admin' or user.role == 'author':
                  return redirect(url_for('dashboard'))
            elif user.role == 'reader':
                 return redirect(url_for('reader_dashboard'))
            else:
                return redirect(url_for('home'))

        flash("Invalid credentials!", "danger")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))
@app.route('/reader_dashboard')
@login_required
def reader_dashboard():
    if current_user.role != 'reader':
        abort(403)

    posts = Post.query.filter(
        Post.status == 'Published',
        ((Post.scheduled_time == None) | (Post.scheduled_time <= datetime.utcnow()))
    ).order_by(Post.created_at.desc()).all()

    return render_template('dashboard_reader.html', posts=posts)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        user_count = User.query.count()
        post_count = Post.query.count()
        comment_count = Comment.query.count()
        category_count = Category.query.count()

        recent_users = User.query.order_by(User.id.desc()).limit(5).all()
        recent_posts = Post.query.order_by(Post.id.desc()).limit(5).all()
        recent_comments = Comment.query.order_by(Comment.id.desc()).limit(5).all()
        scheduled_posts = Post.query.filter_by(status='Scheduled').order_by(Post.scheduled_time.asc()).all()

        return render_template("dashboard_admin.html",
                               user_count=user_count,
                               post_count=post_count,
                               comment_count=comment_count,
                               category_count=category_count,
                               recent_users=recent_users,
                               recent_posts=recent_posts,
                               recent_comments=recent_comments,
                               scheduled_posts=scheduled_posts)

    elif current_user.role == 'author':
              posts = Post.query.filter_by(user_id=current_user.id).all()
              post_ids = [post.id for post in posts]
              comments = Comment.query.filter(Comment.post_id.in_(post_ids)).order_by(Comment.created_at.desc()).all()
              return render_template("dashboard_author.html", posts=posts, comments=comments)
    else:
        abort(403)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Only allow admins
    if current_user.role != 'admin':  # lowercase 'admin'
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Update user info from form
        new_name = request.form.get('name')
        new_email = request.form.get('email')
        new_role = request.form.get('role')
        
        # Basic validation
        if not new_name or not new_email or not new_role:
            flash('Please fill all fields', 'warning')
            return redirect(url_for('edit_user', user_id=user.id))
        
        # Check for email uniqueness if changed
        if new_email != user.email:
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                flash('Email already in use.', 'danger')
                return redirect(url_for('edit_user', user_id=user.id))
        
        user.username = new_name
        user.email = new_email
        user.role = new_role
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('manage_users'))  # Correct route name
    
    return render_template('admin_edit_user.html', user=user)


@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template('admin/users.html', users=users)
@app.route('/admin/posts')
@login_required
def admin_posts():
    if current_user.role != 'admin':
        abort(403)
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', posts=posts)
@app.route('/admin/comments')
@login_required
def admin_comments():
    if current_user.role != 'admin':
        abort(403)
    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('admin/comments.html', comments=comments)
def publish_scheduled_posts():
    now = datetime.now()
    scheduled_posts = Post.query.filter_by(status='Scheduled').filter(Post.scheduled_time <= now).all()

    for post in scheduled_posts:
        post.status = 'Published'
        post.scheduled_time = None  # Clear the scheduled_time

    if scheduled_posts:
        db.session.commit()


@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete yourself!", "danger")
        return redirect(url_for('manage_users'))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('manage_users'))
# @app.route functions

@app.before_request
def before_request_func():
    if current_user.is_authenticated and current_user.role == 'author':
        publish_scheduled_posts()
@app.route('/admin/scheduled-posts')
@login_required
def scheduled_posts():
    if current_user.role != 'admin':
        abort(403)
    
    posts = Post.query.filter_by(status='Scheduled').order_by(Post.scheduled_time.asc()).all()
    return render_template('admin_scheduled_posts.html', posts=posts)

# ==== SEND NOTIFICATION FUNCTION ====
def send_notification(user_id, message):
    notif = Notification(user_id=user_id, message=message)
    db.session.add(notif)
    db.session.commit()

# Notifications list page route
from flask import abort, flash

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/mark_notification_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('notifications'))

@app.route('/mark_all_notifications_read')
@login_required
def mark_all_notifications_read():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notif in notifications:
        notif.is_read = True
    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('notifications'))


# Context processor to inject unread notifications count or list into templates
@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    else:
        notifications = []
    return dict(notifications=notifications)
@app.route('/test_notification')
@login_required
def test_notification():
    send_notification(current_user.id, "This is a test notification from /test_notification")
    flash("Test notification sent!", "success")
    return redirect(url_for('notifications'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if current_user.role != 'author':
        abort(403)

    form = PostForm()
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        # ===== Image Upload =====
        image_file = None
        if form.image.data:
            image_file = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], image_file))

        # ===== Scheduled Time Handling (with safety) =====
        schedule_time = None
        if form.scheduled_time.data:
            if isinstance(form.scheduled_time.data, str):
                try:
                    schedule_time = datetime.strptime(form.scheduled_time.data, '%Y-%m-%dT%H:%M')
                except ValueError:
                    flash("Invalid date/time format for scheduled time.", "danger")
                    return render_template("create_post.html", form=form)
            else:
                schedule_time = form.scheduled_time.data  # already a datetime object

        # ===== Category Validation =====
        selected_category = Category.query.get(form.category.data)
        if not selected_category:
            flash("Invalid category selected.", "danger")
            return render_template("create_post.html", form=form)

        # ===== Create New Post =====
        new_post = Post(
            title=form.title.data,
            content=form.content.data,
            image=image_file,
            category=selected_category.name,
            tags=form.tags.data,
            status=form.status.data if not schedule_time else "Scheduled",
            scheduled_time=schedule_time,
            author=current_user
        )

        db.session.add(new_post)
        db.session.commit()

        # ===== Notification to Admins =====
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            send_notification(admin.id, f"New post pending review: '{new_post.title}' by {current_user.name}")

        flash("Post created successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template("create_post.html", form=form)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Author-only access
    if current_user.role != 'author' or post.author != current_user:
        abort(403)

    # Form initialization
    form = PostForm(obj=post)
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]

    # Set current category ID in dropdown
    current_category = Category.query.filter_by(name=post.category).first()
    if current_category:
        form.category.data = current_category.id

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.tags = form.tags.data

        # Handle Image Update
        if form.image.data:
            image_file = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], image_file))
            post.image = image_file

    
    

        # Update Category
        selected_category = Category.query.get(form.category.data)
        if selected_category:
            post.category = selected_category.name
        else:
            flash("Invalid category selected.", "danger")
            return render_template("edit_post.html", form=form, post=post)

        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template("edit_post.html", form=form, post=post)

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Sirf author apne post ko delete kar sakta hai
    if current_user.role != 'author' or post.author != current_user:
        abort(403)

    # Image delete karo agar image upload hui ho
    if post.image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.", "info")
    return redirect(url_for('dashboard'))
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id, parent_id=None).all()
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            content=form.content.data,
            post_id=post.id,
            user_id=current_user.id if current_user.is_authenticated else None,
            parent_id=int(form.parent_id.data) if form.parent_id.data else None
        )
        db.session.add(new_comment)
        db.session.commit()
        
        # === Send notification to post author if commenter is NOT the author ===
        if current_user.is_authenticated and post.author.id != current_user.id:
            send_notification(post.author.id, 
                f"New comment on your post '{post.title}' by {current_user.name}")

        flash("Comment posted.", "success")
        return redirect(url_for('view_post', post_id=post.id))
    return render_template("post_detail.html", post=post, comments=comments, form=form)

@app.route('/delete_comment/<int:id>')
@login_required
def delete_comment(id):
    if current_user.role != 'admin':
        abort(403)
    comment = Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted.", "info")
    return redirect(request.referrer)
@app.route('/reported_comments')
@login_required
def reported_comments():
    if current_user.role != 'admin':
        abort(403)
    all_reported = Comment.query.filter_by(is_reported=True).all()
    comments = [c for c in all_reported if c.user is not None and c.post is not None]
    return render_template("reported_comments.html", comments=comments)

@app.route('/unreport_comment/<int:id>')
@login_required
def unreport_comment(id):
    if current_user.role != 'admin':
        abort(403)
    comment = Comment.query.get_or_404(id)
    comment.is_reported = False
    db.session.commit()
    flash("Comment unreported successfully.", "success")
    return redirect(url_for('reported_comments'))

@app.route('/report_comment/<int:comment_id>')
@login_required
def report_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.is_reported = True
    db.session.commit()
    flash("Comment reported successfully.", "warning")
    return redirect(request.referrer or url_for('home'))
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    if current_user.role != 'admin':
        abort(403)
    
    category = Category.query.get_or_404(category_id)
    form = CategoryForm(obj=category)

    if form.validate_on_submit():
        category.name = form.name.data
        db.session.commit()
        flash('Category updated successfully.', 'success')
        return redirect(url_for('manage_categories'))

    return render_template('edit_category.html', form=form, category=category)

@app.route('/category/<int:category_id>/delete', methods=['POST', 'GET'])
@login_required
def delete_category(category_id):
    if current_user.role != 'admin':
        abort(403)

    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully.', 'success')
    return redirect(url_for('manage_categories'))


@app.route('/manage_categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if current_user.role != 'admin':
        abort(403)
    form = CategoryForm()
    categories = Category.query.all()
    if form.validate_on_submit():
        category = Category(name=form.name.data)
        db.session.add(category)
        db.session.commit()
        flash("Category added.", "success")
        return redirect(url_for('manage_categories'))
    return render_template("manage_categories.html", form=form, categories=categories)

@app.route('/manage_tags', methods=['GET', 'POST'])
@login_required
def manage_tags():
    if current_user.role != 'admin':
        abort(403)
    form = TagForm()
    tags = Tag.query.all()
    if form.validate_on_submit():
        tag = Tag(name=form.name.data)
        db.session.add(tag)
        db.session.commit()
        flash("Tag added.", "success")
        return redirect(url_for('manage_tags'))
    return render_template("manage_tags.html", form=form, tags=tags)

# ==== PROFILE ROUTE ====
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(
        name=current_user.name,
        email=current_user.email
    )

    if form.validate_on_submit():
        # 1. Update name and email
        current_user.name = form.name.data
        current_user.email = form.email.data

        # 2. Handle profile image upload
        if form.profile_image.data:
            image_file = secure_filename(form.profile_image.data.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file)
            form.profile_image.data.save(image_path)
            current_user.profile_image = image_file  # store filename in db

        # 3. Handle password change
        if form.new_password.data:
            if not form.current_password.data:
                flash("Please enter your current password to change to a new one.", "warning")
                return redirect(url_for('profile'))

            if not check_password_hash(current_user.password, form.current_password.data):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('profile'))

            # Password change confirmed, update password hash
            current_user.password = generate_password_hash(form.new_password.data)
            flash("Password updated successfully.", "success")

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)

@app.route('/admin/pending-posts')
@login_required
def pending_posts():
    if current_user.role != 'admin':
        abort(403)
    posts = Post.query.filter_by(status='Pending').order_by(Post.created_at.desc()).all()
    return render_template('admin_pending_posts.html', posts=posts)
@app.route('/admin/approve-post/<int:post_id>', methods=['POST'])
@login_required
def approve_post(post_id):
    if current_user.role != 'admin':
        abort(403)

    post = Post.query.get_or_404(post_id)
    post.status = 'Published'
    db.session.commit()

    # ✅ Send notification
    send_notification(post.user_id, f"Your post '{post.title}' has been approved!")


    flash('Post approved successfully.', 'success')
    return redirect(url_for('pending_posts'))

@app.route('/admin/reject-post/<int:post_id>', methods=['POST'])
@login_required
def reject_post(post_id):
    if current_user.role != 'admin':
        abort(403)
    post = Post.query.get_or_404(post_id)
    # Option 1: Delete post
    db.session.delete(post)
    # Option 2: Mark as rejected instead of deleting
    # post.status = 'Rejected'
    db.session.commit()
    flash('Post rejected successfully.', 'success')
    return redirect(url_for('pending_posts'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 5  # You can increase this if needed

    if query:
        base_query = Post.query.filter(
            (Post.title.ilike(f'%{query}%')) |
            (Post.content.ilike(f'%{query}%')) |
            (Post.tags.ilike(f'%{query}%'))
        ).filter_by(status='Published')
        
        total = base_query.count()
        results = base_query.order_by(Post.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        pagination = Pagination(page=page, total=total, per_page=per_page, css_framework='bootstrap5')
    else:
        results = []
        pagination = None

    return render_template('search_results.html', query=query, results=results, pagination=pagination)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# ==== RUN APP ====
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if Category.query.count() == 0:
            default_categories = ["Technology", "Health", "Travel", "Education", "Lifestyle"]
            for name in default_categories:
                db.session.add(Category(name=name))
            db.session.commit()
            print("✔ Default categories added.")

    app.run(debug=True)
