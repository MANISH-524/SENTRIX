FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
# SPA fallback so client-side routing works
RUN printf 'server {\n  listen 80;\n  location / {\n    root /usr/share/nginx/html;\n    try_files $uri /index.html;\n  }\n}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
