# FROM node:6-stretch
FROM morgansnyk/goof:1.12.1

LABEL org.opencontainers.image.source="https://github.com/metalstormbass/goof" 
LABEL io.snyk.containers.image.dockerfile="/Dockerfile"

RUN mkdir /usr/src/goof
RUN mkdir /tmp/extracted_files
COPY . /usr/src/goof
WORKDIR /usr/src/goof

RUN npm update
RUN npm install
EXPOSE 3001
EXPOSE 9229
ENTRYPOINT ["npm", "start"]
