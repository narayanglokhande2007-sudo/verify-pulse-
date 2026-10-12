# VerifyPulse Enterprise On-Premise & Air-Gapped Deployment
# Multi-stage Docker container for Bank On-Premise Hosting

FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy application source
COPY api ./api
COPY lib ./lib
COPY pipeline ./pipeline
COPY index.html ./
COPY enterprise.html ./
COPY vercel.json ./

# Set environment
ENV NODE_ENV=production
ENV PORT=3000
ENV VERIFYPULSE_TIER_1_TOTAL_LIMIT=250000
ENV VERIFYPULSE_TIER_2_TOTAL_LIMIT=1000000
ENV VERIFYPULSE_TIER_3_TOTAL_LIMIT=5000000

EXPOSE 3000

CMD ["node", "api/status.js"]
