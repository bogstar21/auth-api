require('dotenv').config()
const express = require('express')
const rateLimit = require('express-rate-limit')
const authRoutes = require('./routes/auth')
const authenticateToken = require('./middleware/auth')

const app = express()

app.use(express.json())
app.use(express.static('public'))

// Rate limiter for auth routes — max 10 requests per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
})

app.use('/auth/login', authLimiter)
app.use('/auth/register', authLimiter)

app.use('/auth', authRoutes)

app.get('/me', authenticateToken, (req, res) => {
  res.json({ user: req.user })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
