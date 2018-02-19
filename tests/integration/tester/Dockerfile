FROM python:3.5
ADD . /code
WORKDIR /code
RUN pip install requests redis pyyaml docker
CMD ["python", "tester.py"]
