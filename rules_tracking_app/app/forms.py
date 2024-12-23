from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length
from .models import User, Behavior


class BehaviorEntryForm(FlaskForm):
    behavior = StringField('Behavior Description', validators=[DataRequired()])
    points = IntegerField('Points', validators=[DataRequired()])
    submit = SubmitField('Add Behavior')


class BehaviorPointsForm(FlaskForm):
    student_name = SelectField('Student Name', validators=[DataRequired()])
    title = SelectField('Behavior Description', validators=[DataRequired()])
    submit = SubmitField('Submit')


    def __init__(self, *args, **kwargs):
        super(BehaviorPointsForm, self).__init__(*args, **kwargs)
        from .models import Behavior
        self.student_name.choices = [
            (user.username, user.username)
            for user in User.query.filter_by(role='student').all()
        ]
        self.title.choices = [(b.description, b.description) for b in Behavior.query.all()]


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=150, message="Username must be between 3 and 150 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message="Password must be at least 6 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match.")
    ])
    role = SelectField('Role', choices=[('student', 'Student'), ('elevated', 'Teacher')])
    submit = SubmitField('Register')




