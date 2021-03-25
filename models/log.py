from db import db


class LogModel(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(40))
    latitude = db.Column(db.String(40))
    longitude = db.Column(db.String(40))
    time_start = db.Column(db.String(10))
    time_end = db.Column(db.String(10))

    user = db.relationship('UserModel')
    username = db.Column(db.String(80), db.ForeignKey('users.username'))

    def __init__(self, username, ip, latitude, longitude, time_start, time_end):
        self.username = username
        self.ip = ip
        self.latitude = latitude
        self.longitude = longitude
        self.time_start = time_start
        self.time_end = time_end

    def json(self):
        return {
            'username': self.username, 'ip': self.ip, 'latitude': self.latitude, 'longitude': self.longitude,
            'time_start': self.time_start, 'time_end': self.time_end
        }

    @classmethod
    def find_log(cls, username, time_start):
        # return cls.query.filter_by(username=username).filter_by(time_start=time_start).first()
        return cls.query.filter_by(username=username).filter_by(time_start=time_start).all()

    # adds itself to the DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Deletes itself from the DB
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
