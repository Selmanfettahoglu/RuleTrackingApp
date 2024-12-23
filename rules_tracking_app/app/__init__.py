from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap5
from flask_migrate import Migrate  # Import Flask-Migrate
import os


db = SQLAlchemy()
migrate = Migrate()  # Initialize Flask-Migrate


def create_app():
    app = Flask(__name__)


    # App configurations
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'behaviors.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)  # Attach Flask-Migrate to the app and db
    Bootstrap5(app)


    # Register routes
    try:
        from .routes import main
        app.register_blueprint(main)
    except ImportError as e:
        print(f"Error importing routes: {e}")


    # Ensure tables are created (only if not using Flask-Migrate)
    with app.app_context():
        db.create_all()


    return app




