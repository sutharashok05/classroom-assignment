import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import session from 'express-session'
import MongoStore from 'connect-mongo'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'

// Import routes
import authRoutes from './routes/auth.js'
import userRoutes from './routes/users.js'
import classRoutes from './routes/classes.js'
import assignmentRoutes from './routes/assignments.js'
import submissionRoutes from './routes/submissions.js'
import commentRoutes from './routes/comments.js'
import notificationRoutes from './routes/notifications.js'
import analyticsRoutes from './routes/analytics.js'
import uploadRoutes from './routes/uploads.js'
import paymentRoutes from './routes/payments.js'

// Import services (simplified for now)

// Import middleware
import logger from './utils/logger.js'

// Load environment variables
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development'
dotenv.config({ path: envFile })

// Fallback to default .env if specific env file doesn't exist
if (!process.env.MONGODB_URI) {
  dotenv.config()
}

// Log environment info for debugging
console.log('🔧 Environment Configuration:')
console.log('NODE_ENV:', process.env.NODE_ENV)
console.log('PORT:', process.env.PORT)
console.log('CLIENT_URL:', process.env.CLIENT_URL)
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Set' : 'Not set')
console.log('SESSION_SECRET:', process.env.SESSION_SECRET ? 'Set' : 'Not set')

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 8080
const isProduction = process.env.NODE_ENV === 'production'

// Security middleware
app.use(helmet({
  contentSecurityPolicy: isProduction ? undefined : false,
  crossOriginEmbedderPolicy: false
}))

// Trust proxy for Vercel
if (isProduction) {
  app.set('trust proxy', 1)
}

// Rate limiting - Very permissive for development and multiple users
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 1000 : 10000, // Very high limits
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for auth routes in development
    return !isProduction && req.path.startsWith('/api/auth')
  }
})

// Auth rate limiting - Removed restrictive limits
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 100 : 1000, // Much higher limits
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  },
  skip: (req) => {
    // Skip rate limiting in development
    return !isProduction
  }
})

// Only apply general rate limiting in production
if (isProduction) {
  app.use(limiter)
}

// CORS configuration - Updated for ngrok + Vercel hybrid deployment
const allowedOrigins = [
  // Development origins
  'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:5000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5000',
  // Production origins
  process.env.CLIENT_URL,
  process.env.FRONTEND_URL,
  process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null,
  'https://gradely.site', // Your current Vercel URL
  // Additional Vercel preview URLs
  'https://classroom-assignment-pqcj-git-main-visheshj2005s-projects.vercel.app',
  'https://classroom-assignment-pqcj-visheshj2005s-projects.vercel.app',
  // Ngrok domains for hybrid deployment
  'https://kobe-nonextensile-socially.ngrok-free.dev/api'
].filter(Boolean)

console.log('🌐 Allowed CORS Origins:', allowedOrigins)

// Custom CORS middleware to ensure no wildcards with credentials
app.use((req, res, next) => {
  const origin = req.headers.origin
  console.log('🔍 CORS Middleware - Origin:', origin, 'Production:', isProduction)
  
  let allowedOrigin = null
  
  // Determine allowed origin
  if (!isProduction) {
    // Development: allow the specific origin or default to localhost
    allowedOrigin = origin || 'http://localhost:5173'
  } else {
    // Production: check against allowed origins
    if (!origin) {
      allowedOrigin = 'https://gradely.site'
    } else if (
      allowedOrigins.includes(origin) ||
      origin.includes('vercel.app') ||
      origin.includes('localhost') ||
      origin.includes('127.0.0.1') ||
      origin.includes('ngrok-free.dev') ||
      origin.includes('ngrok.io')
    ) {
      allowedOrigin = origin
    }
  }
  
  if (allowedOrigin) {
    console.log('✅ CORS Allowed for origin:', allowedOrigin)
    res.header('Access-Control-Allow-Origin', allowedOrigin)
    res.header('Access-Control-Allow-Credentials', 'true')
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,ngrok-skip-browser-warning')
    res.header('Access-Control-Max-Age', '86400') // 24 hours
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      return res.status(200).end()
    }
  } else {
    console.log('❌ CORS Blocked for origin:', origin)
    return res.status(403).json({ error: 'CORS: Origin not allowed' })
  }
  
  next()
})

// Body parsing middleware
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))

// Ensure CORS headers are never overridden
app.use((req, res, next) => {
  // Store original methods
  const originalSetHeader = res.setHeader
  const originalHeader = res.header
  
  // Override setHeader to prevent wildcard with credentials
  res.setHeader = function(name, value) {
    if (name.toLowerCase() === 'access-control-allow-origin' && value === '*' && res.getHeader('access-control-allow-credentials')) {
      console.log('🚫 Prevented wildcard CORS origin with credentials!')
      return originalSetHeader.call(this, name, 'https://classroom-assignment-pqcj.vercel.app')
    }
    return originalSetHeader.call(this, name, value)
  }
  
  // Override header method as well
  res.header = function(name, value) {
    if (name.toLowerCase() === 'access-control-allow-origin' && value === '*' && res.getHeader('access-control-allow-credentials')) {
      console.log('🚫 Prevented wildcard CORS origin with credentials!')
      return originalHeader.call(this, name, 'https://classroom-assignment-pqcj.vercel.app')
    }
    return originalHeader.call(this, name, value)
  }
  
  next()
})

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET || 'your-super-secret-session-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/classroom-assignment',
    touchAfter: 24 * 3600 // lazy session update
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: undefined
  },
  name: 'classroom.sid', // Custom session name
  proxy: true // Always trust proxy
}))

console.log('🍪 Session Configuration:')
console.log('Secure cookies:', isProduction)
console.log('SameSite:', isProduction ? 'none' : 'lax')
console.log('Trust proxy:', isProduction)

// Database connection
const connectDB = async () => {
  try {
    const options = {
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
      maxIdleTimeMS: 30000,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    }

    const conn = await mongoose.connect(
      process.env.MONGODB_URI || 'mongodb://localhost:27017/classroom-assignment',
      options
    )

    logger.info(`📊 MongoDB Connected: ${conn.connection.host}`)

    // Log database events
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error', { error: err.message })
    })

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected')
    })

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected')
    })

  } catch (error) {
    logger.error('Database connection error', { error: error.message })
    process.exit(1)
  }
}

// Note: Static files are served by Vercel frontend, not by this backend

// Routes - Remove auth rate limiting for better development experience
app.use('/api/auth', authRoutes)
app.use('/api/users', userRoutes)
app.use('/api/classes', classRoutes)
app.use('/api/assignments', assignmentRoutes)
app.use('/api/submissions', submissionRoutes)
app.use('/api/comments', commentRoutes)
app.use('/api/notifications', notificationRoutes)
app.use('/api/analytics', analyticsRoutes)
app.use('/api/uploads', uploadRoutes)
app.use('/api/payments', paymentRoutes)

// Debug routes (temporary)
import debugRoutes from './routes/debug.js'
app.use('/api/debug', debugRoutes)

// Health check endpoint
app.get('/api/health', (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'

    res.json({
      success: true,
      message: 'Server is running',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      database: dbStatus,
      sessionStore: 'mongodb',
      authentication: 'session-based',
      version: '2.0.0',
      features: {
        forgotPassword: true,
        sessionManagement: true,
        paymentIntegration: true,
        emailService: process.env.EMAIL_SERVICE || 'mock'
      },
      routes: {
        auth: '/api/auth/login, /api/auth/register, /api/auth/forgot-password',
        users: '/api/users',
        classes: '/api/classes',
        payments: '/api/payments'
      }
    })
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Health check failed',
      error: error.message
    })
  }
})

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'API is working',
    timestamp: new Date().toISOString(),
    headers: req.headers,
    url: req.url,
    method: req.method
  })
})

// API-only backend - frontend is served by Vercel
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API route not found',
    availableRoutes: [
      '/api/health',
      '/api/test',
      '/api/auth/*',
      '/api/users/*',
      '/api/classes/*',
      '/api/assignments/*',
      '/api/payments/*'
    ]
  })
})

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err)
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Internal server error'
  })
})

// Initialize database connection
connectDB().catch(error => {
  console.error('❌ Database connection failed:', error)
})

// Start server (Cloud Run requires the server to always listen)
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`)
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`)
  console.log(`🌐 Client URL: ${process.env.CLIENT_URL || 'http://localhost:5173'}`)
})

// Graceful shutdown for Cloud Run
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully')
  server.close(() => {
    console.log('Process terminated')
    process.exit(0)
  })
})

// Export for Vercel
export default app