FROM node:6-slim
MAINTAINER Identities

COPY .npmrc /app/.npmrc
RUN npm install gulp@3.9.1 tsd -g
EXPOSE 8080

COPY package.json /app/

WORKDIR /app
RUN npm install && tsd install node express

LABEL vulcain.serviceName=sovinty.identities.users-management
LABEL vulcain.version=1.0.201

COPY tsconfig.json package.json gulpFile.js /app/
COPY src /app/src

RUN gulp compile-ts

ENTRYPOINT ["node","--harmony", "dist/index.js"]
