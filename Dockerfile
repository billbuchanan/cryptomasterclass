FROM python:3.7

LABEL version="0.1.0"
LABEL maintainer="Edinburgh Napier University"

COPY . /cryptomasterclass
WORKDIR /cryptomasterclass

# Setup environment
RUN pip install -r requirements.txt --no-cache-dir
RUN pip install jupyterlab

# Expose port for jupyter lab
EXPOSE 8888

# Enter into jupyter lab
ENTRYPOINT ["jupyter", "lab","--ip=0.0.0.0","--allow-root"]