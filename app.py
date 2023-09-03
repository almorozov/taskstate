from tsapp.routes import app, db
from tsapp.models import TS_User, TS_Task
import time

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        time.sleep(5)
        app.run()
