FROM node:24-alpine AS build
WORKDIR /console
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:stable-alpine
ENV MASP_BACKEND_URL=http://app:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /console/dist /usr/share/nginx/html/console
EXPOSE 8080
