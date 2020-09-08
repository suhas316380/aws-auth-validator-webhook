FROM python:3.7
RUN apt update && apt-get install -y vim
RUN pip3 install kubernetes flask jsonpatch gunicorn boto3
COPY ./aws-auth-checker /app
EXPOSE 443
CMD gunicorn --chdir /app --certfile=/etc/webhook/certs/cert.pem --keyfile=/etc/webhook/certs/key.pem --worker-tmp-dir /dev/shm --log-file=- --bind 0.0.0.0:443 wsgi:admission_controller