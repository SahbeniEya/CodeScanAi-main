# Use a vulnerable base image
FROM debian:9

# Install vulnerable packages
RUN apt-get update && apt-get install -y \
    python3=3.5.3-1 \
    python3-pip=9.0.1-2+deb9u1 \
    nginx=1.10.3-1+deb9u1 \
    openssl=1.1.0l-1~deb9u1

# Install vulnerable Python packages
RUN pip3 install \
    flask==0.12.2 \
    django==1.11.0 \
    requests==2.18.0

# Copy application files
COPY . /app
WORKDIR /app

# Expose port
EXPOSE 5000

# Run the application
CMD ["python3", "run_web.py"]
