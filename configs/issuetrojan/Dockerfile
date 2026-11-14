FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pytest==8.4.2 mpmath==1.3.0 urllib3==2.5.0 charset-normalizer==3.4.3 idna==3.10 certifi==2025.8.3
ARG LOCAL_DUMMY_PACKAGES=0
COPY local_dummy_packages.py /tmp/local_dummy_packages.py
RUN if [ "$LOCAL_DUMMY_PACKAGES" = "1" ]; then \
      python /tmp/local_dummy_packages.py /opt/dummy-package-wheelhouse && \
      printf '[global]\nno-index = true\nfind-links = /opt/dummy-package-wheelhouse\n' > /etc/pip.conf && \
      rm /tmp/local_dummy_packages.py; \
    else \
      rm /tmp/local_dummy_packages.py; \
    fi
WORKDIR /repo
