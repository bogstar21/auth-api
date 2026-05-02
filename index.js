require('dotenv').config()
const express = require('express')
const authRoutes = require('./routes/auth')

const app = express()
app.use(express.json())

app.use('/auth', authRoutes)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})

const authenticateToken = require('./middleware/auth')

// Protected route — requires valid token
app.get('/me', authenticateToken, (req, res) => {
    res.json({ user: req.user })
})