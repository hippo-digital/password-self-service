FROM python:3.6.2
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install --default-timeout=900 -r requirements.txt
COPY . .
ENTRYPOINT ["python"]
CMD ["polling_test_harness.py"]
