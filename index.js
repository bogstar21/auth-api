require('dotenv').config()
const express = require('express')
const authRoutes = require('./routes/auth')
const authenticateToken = require('./middleware/auth')

const app = express()

app.use(express.json())
app.use(express.static('public'))

app.use('/auth', authRoutes)

app.get('/me', authenticateToken, (req, res) => {
  res.json({ user: req.user })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
