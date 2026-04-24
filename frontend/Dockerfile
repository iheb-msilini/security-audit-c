FROM node:20-alpine

WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

COPY package*.json .
RUN npm install

COPY . .

CMD ["npm", "run", "dev"]
