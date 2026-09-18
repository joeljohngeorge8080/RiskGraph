# syntax=docker/dockerfile:1.7
# Dev target runs Vite; prod target builds static assets for Caddy (Phase 18).
FROM node:20-alpine AS dev
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
EXPOSE 5173
CMD ["npm", "run", "dev"]

FROM dev AS build
RUN npm run build

FROM scratch AS static
COPY --from=build /app/dist /dist
