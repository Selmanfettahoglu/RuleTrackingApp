from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from functools import wraps
import csv
from . import db
from app.models import Behavior, User, SharedStudent
from .forms import BehaviorEntryForm, BehaviorPointsForm, RegisterForm
from werkzeug.security import generate_password_hash
from flask import session
from werkzeug.security import generate_password_hash
from .models import User
from . import db


main = Blueprint('main', __name__, template_folder='templates')

def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('You must log in to access this page.', 'warning')
                return redirect(url_for('main.login'))
            if session.get('role') not in required_roles:
                flash('You do not have the required permissions to access this page.', 'danger')
                return redirect(url_for('main.home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator





@main.route('/admin_home')
@role_required('super_admin')  # Ensure only super admins can access this route
def admin_home():
    teachers = User.query.filter_by(role='elevated').all()
    return render_template('admin_home.html', teachers=teachers)







def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # Flash session expired only if not already shown
            if not session.get('session_expired_shown'):
                flash('Your session has expired. Please log in again.', 'warning')
                session['session_expired_shown'] = True
            return redirect(url_for('main.login'))
        session.pop('session_expired_shown', None)  # Reset flag after successful login
        return f(*args, **kwargs)
    return decorated_function



# Load users from JSON
def load_users():
    """Load users from the database."""
    from .models import User
    users = User.query.all()
    return {user.username: {'password': user.password, 'role': user.role} for user in users}



# Role required decorator




@main.route('/student_home')
@login_required
def student_home():
    return render_template('student_home.html', username=session.get('username'))




@main.route('/teacher_home')
@role_required('elevated', 'super_admin')  # Only teachers can access this
def teacher_home():
    teacher_id = session.get('user_id')  # Current teacher's ID


    # Fetch students created by this teacher
    my_students = User.query.filter_by(teacher_id=teacher_id, role='student').all()


    # Fetch students shared with this teacher
    shared_students = (
        User.query.join(SharedStudent, SharedStudent.student_id == User.id)
        .filter(SharedStudent.target_teacher_id == teacher_id)
        .all()
    )

    return render_template(
        'teacher_home.html',
        username=session.get('username'),
        my_students=my_students,
        shared_students=shared_students
    )







@main.route('/share_student/<int:student_id>', methods=['POST'])
@role_required('elevated', 'super_admin')
def share_student(student_id):
    teacher_id = session.get('user_id')  # Current teacher's ID
    target_teacher_id = request.form.get('target_teacher_id')  # ID of the teacher to share with


    # Ensure the student belongs to the current teacher
    student = User.query.filter_by(id=student_id, teacher_id=teacher_id, role='student').first()
    target_teacher = User.query.filter_by(id=target_teacher_id, role='elevated').first()


    if not student or not target_teacher:
        flash('Invalid student or teacher.', 'danger')
        return redirect(url_for('main.share_students_page'))


    # Check if the student is already shared with this teacher
    existing_share = SharedStudent.query.filter_by(
        student_id=student.id,
        target_teacher_id=target_teacher.id
    ).first()


    if existing_share:
        flash(f'{student.username} is already shared with {target_teacher.username}.', 'info')
    else:
        # Add a shared record
        shared_record = SharedStudent(
            student_id=student.id,
            target_teacher_id=target_teacher.id,
            shared_by_teacher_id=teacher_id
        )
        db.session.add(shared_record)
        db.session.commit()
        flash(f'{student.username} successfully shared with {target_teacher.username}!', 'success')


    return redirect(url_for('main.share_students_page'))







@main.route('/share_students_page', methods=['GET'])
@role_required('elevated', 'super_admin')
def share_students_page():
    teacher_id = session.get('user_id')  # Current teacher's ID
    # Fetch students created by this teacher
    students = User.query.filter_by(teacher_id=teacher_id, role='student').all()
    # Fetch all teachers excluding the current teacher
    teachers = User.query.filter(User.role == 'elevated', User.id != teacher_id).all()
    return render_template('share_students.html', students=students, teachers=teachers)







@main.route('/register_teacher', methods=['GET', 'POST'])
def register_teacher():
    """
    Register route for teachers. Only accessible publicly.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = 'elevated'  # Fixed role for teachers


        # Check if the teacher already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('main.register_teacher'))


        # Create a new teacher account
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_teacher = User(username=username, password=hashed_password, role=role)
        db.session.add(new_teacher)
        db.session.commit()


        flash('Teacher account created successfully! Please log in.', 'success')
        return redirect(url_for('main.admin_home'))


    return render_template('register_teacher.html')




@main.route('/register_student', methods=['GET', 'POST'])
@role_required('elevated', 'super_admin')
def register_student():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')


        # Get the teacher ID from the session
        teacher_id = session.get('user_id')


        # Check if the student already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('main.register_student'))


        # Create the new student
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role='student', teacher_id=teacher_id)
        db.session.add(new_user)
        db.session.commit()


        flash(f'Student {username} successfully created!', 'success')
        return redirect(url_for('main.teacher_home'))


    return render_template('register_student.html')






@main.route('/delete_student/<int:student_id>', methods=['POST'])
@role_required('elevated', 'super_admin')  # Allow both teachers and admins to access this
def delete_student(student_id):
    user_role = session.get('role')  # Get the role of the logged-in user
    user_id = session.get('user_id')  # Get the current user's ID


    if user_role == 'elevated':  # If the user is a teacher
        # Teachers can delete only the students they created
        student = User.query.filter_by(id=student_id, teacher_id=user_id, role='student').first()
        if not student:
            flash("Student not found or you don't have permission to delete this student.", "danger")
            return redirect(url_for('main.student_list'))
    elif user_role == 'super_admin':  # If the user is an admin
        # Admins can delete any student
        student = User.query.filter_by(id=student_id, role='student').first()
        if not student:
            flash("Student not found.", "danger")
            return redirect(url_for('main.student_list'))
    else:
        # Unauthorized access
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for('main.home'))


    # Remove all shared records for this student
    SharedStudent.query.filter_by(student_id=student.id).delete()


    # Delete the student
    db.session.delete(student)
    db.session.commit()


    flash(f"Student {student.username} has been deleted successfully.", "success")
    return redirect(url_for('main.student_list'))








# Routes
@main.route('/')
# @login_required
def home():
    students = []
    if session.get('role') == 'elevated':
        from .models import User
        students = User.query.filter_by(role='student').all()
    return render_template('index.html', username=session.get('username'))

import logging
logging.basicConfig(level=logging.DEBUG)


def flash_once(message, category='message'):
    """Custom flash function to prevent duplicate flash messages."""
    if message not in session.get('_flashed_messages', []):
        flash(message, category)
        session.setdefault('_flashed_messages', []).append(message)
        logging.debug(f"Flashed: {message}")


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')


        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Set user information in the session
            session['username'] = user.username
            session['role'] = user.role
            session['user_id'] = user.id  # Store the user ID in the session
            session.permanent = True
            flash('Login successful!', 'success')


            # Redirect based on role
            if user.role == 'super_admin':
                return redirect(url_for('main.admin_home'))
            elif user.role == 'elevated':
                return redirect(url_for('main.teacher_home'))
            else:
                return redirect(url_for('main.student_home'))
        else:
            flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html')



@main.route('/create_teacher', methods=['POST'])
@role_required('super_admin')
def create_teacher():
    username = request.form.get('username')
    password = request.form.get('password')

    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Teacher username already exists. Please choose a different one.', 'danger')
        return redirect(url_for('main.admin_home'))

    # Create the teacher account
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_teacher = User(username=username, password=hashed_password, role='elevated')
    db.session.add(new_teacher)
    db.session.commit()

    flash(f'Teacher "{username}" created successfully!', 'success')
    return redirect(url_for('main.admin_home'))

@main.route('/delete_teacher/<int:teacher_id>', methods=['POST'])
@role_required('super_admin')
def delete_teacher(teacher_id):
    # Fetch the teacher by ID
    teacher = User.query.filter_by(id=teacher_id, role='elevated').first()
    if not teacher:
        flash('Teacher not found.', 'danger')
        return redirect(url_for('main.admin_home'))

    # Delete the teacher
    db.session.delete(teacher)
    db.session.commit()

    flash(f'Teacher "{teacher.username}" deleted successfully!', 'success')
    return redirect(url_for('main.admin_home'))





@main.route('/students_points')
@role_required('elevated', 'super_admin')  # Only teachers can access this
def students_points():
    # Fetch all students and their points
    students_data = []


    try:
        # Fetch all students
        students = User.query.filter_by(role='student').all()


        # Fetch each student's behavior data
        for student in students:
            behaviors_count = {}
            total_points = {}
            total_points_lost = 0
            initial_points = 100


            # Dynamically fetch all behaviors from the database
            all_behaviors = Behavior.query.all()
            for behavior in all_behaviors:
                behaviors_count[behavior.description] = 0
                total_points[behavior.description] = 0


            # Read data from CSV and process it
            with open('behavior_points.csv', mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0].strip().lower() == student.username.lower():
                        behavior = row[1].strip()
                        points = int(row[2])
                        if behavior in behaviors_count:
                            behaviors_count[behavior] += 1
                            total_points[behavior] += points
                        total_points_lost += points


            # Calculate the percentage of total points lost
            percentage = (total_points_lost / initial_points) * 100


            # Prepare data for each student
            students_data.append({
                'username': student.username,
                'behaviors_count': behaviors_count,
                'total_points': total_points,
                'total_points_lost': total_points_lost,
                'percentage': percentage
            })
    except Exception as e:
        flash(f"Error loading student points data: {e}", "danger")


    return render_template('students_points.html', students_data=students_data)









@main.route('/logout')
def logout():
    role = session.get('role')  # Save role for redirecting
    session.clear()  # Clear the session
    flash('You have been logged out.', 'info')  # Flash logout message
    if role == 'elevated':
        return redirect(url_for('main.teacher_home'))
    return redirect(url_for('main.student_home'))


@main.route('/behavior_form', methods=['GET', 'POST'])
@role_required('elevated', 'super_admin')  # Only accessible by elevated users
def behavior_form():
    form = BehaviorPointsForm()


    if form.validate_on_submit():
        # Retrieve the form data
        student_name = form.student_name.data
        title = form.title.data


        # Fetch the points for the selected behavior
        behavior = Behavior.query.filter_by(description=title).first()
        if behavior:
            points = behavior.points
        else:
            flash('Behavior not found in the database.', 'danger')
            return redirect(url_for('main.behavior_form'))


        # Write the data to the CSV file
        try:
            with open('behavior_points.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([student_name, title, points])
            flash('Behavior points added successfully!', 'success')
        except Exception as e:
            flash(f'Error saving to file: {e}', 'danger')


        # Redirect to the home page after successful submission
        return redirect(url_for('main.teacher_home'))


    return render_template('behavior_form.html', form=form)


@main.route('/student_list')
@role_required('elevated', 'super_admin')  # Allow both teachers and admins to access this
def student_list():
    # Check if the current user is an admin
    if session.get('role') == 'super_admin':
        # Admins can view all students
        all_students = User.query.filter_by(role='student').all()
        my_students = []
        shared_students = []
    else:
        teacher_id = session.get('user_id')  # Current teacher's ID


        # Fetch students created by this teacher
        my_students = User.query.filter_by(teacher_id=teacher_id, role='student').all()


        # Fetch students shared with this teacher
        shared_students = (
            User.query.join(SharedStudent, SharedStudent.student_id == User.id)
            .filter(SharedStudent.target_teacher_id == teacher_id)
            .all()
        )
        all_students = []  # For teachers, this will be empty


    return render_template(
        'student_list.html',
        all_students=all_students,
        my_students=my_students,
        shared_students=shared_students
    )










@main.route('/add_behavior_teacher', methods=['GET', 'POST'])
@role_required('elevated', 'super_admin')
def add_behavior_teacher():
    form = BehaviorEntryForm()
    if form.validate_on_submit():
        existing_behavior = Behavior.query.filter_by(description=form.behavior.data).first()
        if existing_behavior:
            flash("This behavior already exists!", "warning")
        else:
            new_behavior = Behavior(description=form.behavior.data, points=form.points.data)
            db.session.add(new_behavior)
            db.session.commit()
            flash("Behavior added successfully!", "success")

        return redirect(url_for('main.add_behavior_teacher'))


    behaviors = Behavior.query.all()
    return render_template('add_behavior_teacher.html', form=form, behaviors=behaviors)


@main.route('/teacher_dashboard')
@role_required('elevated', 'super_admin')  # Only teachers can access this
def teacher_dashboard():
    # Fetch all students from the database
    students = User.query.filter_by(role='student').all()
    print(f"students: {students}")
    return render_template('index.html', username=session.get('username'), students=students)

@main.route('/student_behavior_table/<student_name>')
@login_required
def student_behavior_table(student_name):
    # Initialize variables
    behaviors_count = {}
    total_points = {}
    total_points_lost = 0
    initial_points = 100


    try:
        # Dynamically fetch all behaviors from the database
        all_behaviors = Behavior.query.all()
        for behavior in all_behaviors:
            behaviors_count[behavior.description] = 0
            total_points[behavior.description] = 0


        # Read data from CSV and process it
        with open('behavior_points.csv', mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0].strip().lower() == student_name.lower():
                    behavior = row[1].strip()
                    points = int(row[2])
                    if behavior in behaviors_count:
                        behaviors_count[behavior] += 1
                        total_points[behavior] += points
                    total_points_lost += points


        # Calculate the percentage of total points lost
        percentage = (total_points_lost / initial_points) * 100


        # Prepare table data
        table_data = []
        for behavior, count in behaviors_count.items():
            table_data.append({
                'behavior': behavior,
                'occurrences': count,
                'total_points': total_points[behavior]
            })


        # Determine message based on percentage
        internet_message = None
        if 6 <= percentage < 10:
            internet_message = "1 hour less internet"
        elif 10 <= percentage < 15:
            internet_message = "2 hours less internet"
        elif 15 <= percentage < 20:
            internet_message = "3 hours less internet"


        # Render the template with the data
        return render_template(
            'student_behavior_table.html',
            student_name=student_name,
            table_data=table_data,
            percentage=percentage,
            internet_message=internet_message
        )
    except Exception as e:
        flash(f"Error loading student behavior data: {e}", "danger")
        return redirect(url_for('main.home'))


@main.route('/teacher_view_student/<student_name>')
@role_required('elevated', 'super_admin')  # Ensure only teachers can access this route
def teacher_view_student(student_name):
    try:
        # Fetch all behaviors dynamically from the database
        all_behaviors = Behavior.query.all()
        if not all_behaviors:
            flash("No behaviors defined in the system. Please add behaviors first.", "warning")
            return redirect(url_for('main.student_home'))

        # Initialize behavior tracking
        behaviors_count = {behavior.description: 0 for behavior in all_behaviors}
        total_points = {behavior.description: 0 for behavior in all_behaviors}
        total_points_lost = 0
        initial_points = 100

        # Read the behavior points from the CSV file
        try:
            with open('behavior_points.csv', mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[0].strip().lower() == student_name.lower():
                        behavior = row[1].strip()
                        points = int(row[2])
                        if behavior in behaviors_count:
                            behaviors_count[behavior] += 1
                            total_points[behavior] += points
                        total_points_lost += points
        except FileNotFoundError:
            flash("Behavior points file not found. Please ensure the file exists.", "danger")
            return redirect(url_for('main.home'))
        except Exception as e:
            flash(f"Error reading behavior points file: {e}", "danger")
            return redirect(url_for('main.home'))

        # Calculate the percentage of points lost
        percentage = (total_points_lost / initial_points) * 100 if total_points_lost > 0 else 0

        # Prepare table data
        table_data = [
            {
                'behavior': behavior,
                'occurrences': count,
                'total_points': total_points[behavior]
            }
            for behavior, count in behaviors_count.items()
        ]

        # Determine the message based on the percentage
        internet_message = None
        if 6 <= percentage < 10:
            internet_message = "1 hour less internet"
        elif 10 <= percentage < 15:
            internet_message = "2 hours less internet"
        elif 15 <= percentage < 20:
            internet_message = "3 hours less internet"

        # Render the student behavior table template
        return render_template(
            'student_behavior_table.html',
            student_name=student_name,
            table_data=table_data,
            percentage=percentage,
            internet_message=internet_message
        )
    except Exception as e:
        flash(f"Unexpected error: {e}", "danger")
        return redirect(url_for('main.home'))





@main.route('/student_graph/<student_name>')
def student_graph(student_name):
    # Logic for displaying student graphs
    pass  # Add logic here






