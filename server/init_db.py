from flask_app import app, db

print("Initializing Database...")
with app.app_context():
    db.create_all()
    print("Database `shortener.db` created successfully.")
