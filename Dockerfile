FROM node:20-alpine
WORKDIR /app

RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci

COPY patch.js .
# Using ENTRYPOINT instead of CMD to allow passing arguments to the script directly
ENTRYPOINT ["node", "patch.js"]
