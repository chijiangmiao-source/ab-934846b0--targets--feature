FROM node:20-alpine

WORKDIR /app

# 无第三方运行时依赖，直接拷贝源码
COPY package.json ./
COPY src ./src
COPY web ./web
COPY server ./server
COPY scripts ./scripts
COPY tests ./tests

# 构建静态页面（dist/），web 与 verify 两个服务共用同一镜像
RUN node scripts/build.js

ENV PORT=8080 \
    WEB_ROOT=/app/dist

EXPOSE 8080

CMD ["node", "server/server.js"]
