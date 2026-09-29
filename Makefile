install:
	python -m pip install -r requirements.txt
run:
	uvicorn backend.main:app --reload
test:
	pytest -q
