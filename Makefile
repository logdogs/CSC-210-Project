make:
	cd CCE; \
	python3 -m venv venv; \
	. venv/bin/activate; \
	pip install Flask; \
	pip install flask_sqlalchemy; \
	pip install bcrypt; \
	pip install flask_mail; \
	pip install onetimepass; \
	pip install pyqrcode; \
	pip install flask_wtf; \
	pip install flask_login; \
	python3 app.py