FROM node:18-alpine3.16
WORKDIR /usr/app
COPY package*.json ./
RUN npm install
COPY . .

ENV PORT 3002

EXPOSE $PORT
CMD ["node", "app.js"]