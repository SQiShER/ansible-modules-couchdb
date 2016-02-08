FROM python:2.7-slim
RUN mkdir -p /ci/test/integration
WORKDIR /ci/test/integration
RUN apt-get update && apt-get install -y gcc libc-dev
COPY requirements.txt /
RUN pip install --upgrade -r /requirements.txt
CMD [ "ansible-playbook", "-i", "inventory", "playbook.yml" ]
COPY . /ci
