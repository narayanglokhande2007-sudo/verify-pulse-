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
COPY public ./public
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

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/status || exit 1

CMD ["npm", "start"]
