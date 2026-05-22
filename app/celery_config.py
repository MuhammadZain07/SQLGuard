from config import Config

def make_celery(app, celery):
    # Configure the existing celery instance instead of creating a new one
    celery.conf.update(
        broker_url=Config.CELERY_BROKER_URL,
        result_backend=Config.CELERY_RESULT_BACKEND,
        broker_connection_retry_on_startup=True,  # add this
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery