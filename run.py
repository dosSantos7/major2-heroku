from app import app
from db import db

db.init_app(app)


# this function runs before any http request is made - used for creation of rss. like tables
@app.before_first_request
def create_table():
    db.create_all()  # creates all necessary tables automatically