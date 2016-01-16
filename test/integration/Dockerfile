FROM python:2.7-alpine
RUN mkdir -p /ci/test/integration
WORKDIR /ci/test/integration
RUN apk update && apk add gcc libc-dev
COPY requirements.txt /
RUN pip install --upgrade -r /requirements.txt
CMD [ "ansible-playbook", "-i", "inventory", "playbook.yml" ]
