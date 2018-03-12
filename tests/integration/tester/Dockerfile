FROM python:3.5
RUN pip install requests redis pyyaml docker
ADD . /code
WORKDIR /code
CMD ["python", "tester.py"]
