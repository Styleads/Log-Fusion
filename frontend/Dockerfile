FROM node:20-alpine

WORKDIR /app

# Install dependencies first for efficient layer caching
COPY package*.json ./
RUN npm install

# Copy source code and configuration files
COPY . .

# Expose Vite dev server port
EXPOSE 3000

ENV HOST=0.0.0.0 \
    PORT=3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
