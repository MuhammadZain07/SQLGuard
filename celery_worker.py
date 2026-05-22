from app import create_app, celery

# create_app() configures the celery instance
flask_app = create_app()

# Now celery is fully configured — worker can use it
app = celery