import click
from getpass import getpass
from gposerver import create_app, db, User, Device, EpisodeAction

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return dict(app=app, db=db, User=User, Device=Device, EpisodeAction=EpisodeAction)

@app.cli.command()
def adduser():
    """Add new user."""
    username = input("Username: ")
    password = getpass("Password: ")
    u = User(username, password)
    db.session.add(u)
    db.session.commit() 

@app.cli.command()
def init():
    """Initialise database."""
    db.create_all()
