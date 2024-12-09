from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_portal.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ----------------- Database Models -----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_recruiter = db.Column(db.Boolean, default=False)
    jobs = db.relationship('Job', backref='recruiter', lazy=True)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recruiter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    recruiter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cover_letter = db.Column(db.Text)
app.app_context().push()
db.create_all()
# ----------------- Login Manager -----------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- Routes -----------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')  # recruiter or job_seeker
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
            return redirect(url_for('signup'))
        
        is_recruiter = (role == 'recruiter')
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            is_recruiter=is_recruiter
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Account created successfully!')
        return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password!')
            return redirect(url_for('login'))
        
        login_user(user)
        flash('Logged in successfully!')
        if user.is_recruiter:
            return redirect(url_for('recruiter_profile'))
        else:
            return redirect(url_for('job_seeker_profile'))
        
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/edit/<int:id>',methods=['POST','GET'])
@login_required
def edit(id):
    job = Job.query.get(id)
    if request.method=='POST':
        job.title=request.form['title']
        job.description=request.form['description']
        db.session.commit()
        return redirect(url_for('recruiter_profile',))
    
    return render_template("recruiter_post.html", job=job)



@app.route('/jobs', methods=['GET', 'POST'])
@login_required
def jobs():
    if current_user.is_recruiter:
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            new_job = Job(title=title, description=description, recruiter_id=current_user.id)
            db.session.add(new_job)
            db.session.commit()
            flash('Job posted successfully!')
            return redirect(url_for('recruiter_profile'))          
        # If GET request, show the job posting form
        return render_template('recruiter_post.html')

    else:
        available_jobs = Job.query.all()
        return render_template('job_seeker_jobs.html', jobs=available_jobs)

        

@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply(job_id):
    if current_user.is_recruiter:
        flash('Only job seekers can apply to jobs.')
        return redirect(url_for('jobs'))
    
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        cover_letter = request.form.get('cover_letter')
        application = Application(
            job_id=job.id,
            applicant_id=current_user.id,
            cover_letter=cover_letter
        )
        db.session.add(application)
        db.session.commit()
        flash('Application submitted successfully!')
        return redirect(url_for('jobs'))
    
    return render_template('application.html', job=job)
@app.route('/recruiter_profile')
@login_required
def recruiter_profile():
    if current_user.is_recruiter:
        return render_template('recruiter_profile.html',current_user=current_user)
    else:
        flash('You need to be a recruiter to view this page.')
        return redirect(url_for('home'))

@app.route('/display')
@login_required
def display():
    jobs=Job.query.all()
    return render_template('job_seeker_jobs.html',jobs=jobs)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    job=Job.query.get(id)
    db.session.delete(job)
    db.session.commit()
    return redirect(url_for('recruiter_profile'))

@app.route('/job_seeker_profile')
@login_required
def job_seeker_profile():
    if not current_user.is_recruiter:
        return render_template('job_seeker_profile.html')
    else:
        flash('You need to be a job seeker to view this page.')
        return redirect(url_for('home'))


# ----------------- Database Setup -----------------



 

# ----------------- Run Application -----------------

if __name__ == '__main__':
    app.run(debug=True)
