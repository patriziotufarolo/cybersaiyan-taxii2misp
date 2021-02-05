FROM python:3.7
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY cs.py ./
CMD [ "python", "./cs.py" ]
EXPOSE 8080
