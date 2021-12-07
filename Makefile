make:
	cd CCE; \
	python3 -m venv venv; \
	. venv/bin/activate; \
	pip install Flask; \
	pip install flask_sqlalchemy; \
	pip install bcrypt; \
	pip install flask_mail; \
	open http://localhost:5000; \
	python3 app.py
	