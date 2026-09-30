"""One-time repair: rebuild ONLY the news tables so they match app.py.

Your complaints, contacts and admin accounts are NOT touched.
Any existing news posts are deleted (they were test data from earlier attempts).
A backup copy of the database file is made first.
Run from the project folder:   python reset_news_tables.py
"""
import os, shutil
from datetime import datetime
from app import app, db, NewsPost, NewsImage

with app.app_context():
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if uri.startswith("sqlite:///"):
        path = uri.replace("sqlite:///", "", 1)
        if not os.path.isabs(path):
            for base in (app.instance_path, os.path.dirname(os.path.abspath(__file__))):
                if os.path.exists(os.path.join(base, path)):
                    path = os.path.join(base, path); break
        if os.path.exists(path):
            backup = f"{path}.backup-{datetime.now():%Y%m%d-%H%M%S}"
            shutil.copy2(path, backup)
            print("Backup saved:", backup)

    db.session.execute(db.text("DROP TABLE IF EXISTS news_images"))
    db.session.execute(db.text("DROP TABLE IF EXISTS news_posts"))
    db.session.commit()
    NewsPost.__table__.create(db.engine)
    NewsImage.__table__.create(db.engine)
    print("Done: news_posts and news_images rebuilt to match the app.")
