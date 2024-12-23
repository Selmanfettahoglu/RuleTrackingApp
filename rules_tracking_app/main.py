from app import create_app, db
from datetime import timedelta


app = create_app()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for User and Behavior
    app.run(debug=True, port=5005)




