CyberSafe Connect Architecture Rules

1. Every backend component must live inside /services

2. Each service is an independent Docker container

3. Each service follows:

    app.py
    routes.py
    services.py
    models.py
    schemas.py
    config.py
    security.py (if needed)

4. No additional backend folder allowed

5. No secrets committed to Git

6. Every dependency version must be pinned

7. No direct push to master/main

8. Pull Request mandatory before merge