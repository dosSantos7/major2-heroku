from db import db


class UserModel(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(80))
    phone_number = db.Column(db.String(10))
    safe_ip = db.Column(db.String(40))
    safe_latitude = db.Column(db.String(40))
    safe_longitude = db.Column(db.String(40))
    safe_time_start = db.Column(db.String(10))
    safe_time_end = db.Column(db.String(10))

    logs = db.relationship('LogModel', lazy='dynamic')

    def __init__(self, username, password, phone_number, safe_ip, safe_latitude, safe_longitude, safe_time_start, safe_time_end):
        self.username = username
        self.password = password
        self.phone_number = phone_number
        self.safe_ip = safe_ip
        self.safe_latitude = safe_latitude
        self.safe_longitude = safe_longitude
        self.safe_time_start = safe_time_start
        self.safe_time_end = safe_time_end

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    def json(self):
        return {'name': self.username, 'logs': [log.json() for log in self.logs.all()]}

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()