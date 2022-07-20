FROM python:3.9-slim-buster
USER root
RUN apt-get update && apt-get install -y unzip abootimg curl cpio
WORKDIR /home/8k
COPY adbd ./
COPY slua ./
COPY sluac ./
COPY bootpatch.sh ./
RUN chmod +x ./bootpatch.sh
ENTRYPOINT /home/8k/bootpatch.sh
