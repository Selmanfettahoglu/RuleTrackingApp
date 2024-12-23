from werkzeug.security import check_password_hash
from . import db




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Role: 'student' or 'elevated' (teacher)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Reference to teacher's ID


    # Relationship for teacher-student association
    students = db.relationship(
        'User',
        backref=db.backref('teacher', remote_side=[id]),
        lazy='dynamic',
        cascade="all, delete-orphan"
    )


    def check_password(self, password):
        """
        Verify the provided password against the hashed password.
        """
        return check_password_hash(self.password, password)


    def __repr__(self):
        """
        Representation of the User object.
        """
        return f"<User {self.username} ({self.role})>"


    def is_teacher(self):
        """
        Check if the user is a teacher.
        """
        return self.role == 'elevated'


    def is_student(self):
        """
        Check if the user is a student.
        """
        return self.role == 'student'




class Behavior(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False, unique=True)
    points = db.Column(db.Integer, nullable=False)


    def __repr__(self):
        """
        Representation of the Behavior object.
        """
        return f"<Behavior {self.description}>"




class SharedStudent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ID of the shared student
    target_teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Teacher receiving the shared student
    shared_by_teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Teacher sharing the student


    # Relationships for shared students
    student = db.relationship("User", foreign_keys=[student_id], backref="shared_records")
    target_teacher = db.relationship("User", foreign_keys=[target_teacher_id], backref="received_students")
    shared_by_teacher = db.relationship("User", foreign_keys=[shared_by_teacher_id], backref="shared_students")


    def __repr__(self):
        """
        Representation of the SharedStudent object.
        """
        return f"<SharedStudent student_id={self.student_id} target_teacher_id={self.target_teacher_id} shared_by_teacher_id={self.shared_by_teacher_id}>"




