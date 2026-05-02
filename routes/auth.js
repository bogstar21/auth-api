const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const pool = require('../db')
const crypto = require('crypto')


const router = express.Router()
const SALT_ROUNDS = 10

function generateRefreshToken() {
    return crypto.randomBytes(64).toString('hex')
}

// POST /auth/register
router.post('/register', async (req, res) => {
    const { email, password } = req.body

    // Basic validation
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' })
    }

    try {
        // 1. Check if user already exists
        const existing = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        )

        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Email already registered' })
        }

        // 2. Hash the password — bcrypt does the heavy lifting
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS)

        // 3. Store the user
        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
            [email, password_hash]
        )

        res.status(201).json({ user: result.rows[0] })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

// POST /auth/login
router.post('/login', async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' })
    }

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        )

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        const user = result.rows[0]
        const valid = await bcrypt.compare(password, user.password_hash)

        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }

        // Short-lived access token — 15 minutes
        const accessToken = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        )

        // Long-lived refresh token — 7 days, stored in DB
        const refreshToken = generateRefreshToken()
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

        await pool.query(
            'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, refreshToken, expiresAt]
        )

        res.json({ accessToken, refreshToken })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

// POST /auth/refresh
router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body

    if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' })
    }

    try {
        // Find the token in DB
        const result = await pool.query(
            'SELECT * FROM refresh_tokens WHERE token = $1',
            [refreshToken]
        )

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid refresh token' })
        }

        const stored = result.rows[0]

        // Check if it has expired
        if (new Date() > new Date(stored.expires_at)) {
            await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [stored.id])
            return res.status(401).json({ error: 'Refresh token expired' })
        }

        // Issue a new access token
        const userResult = await pool.query(
            'SELECT id, email FROM users WHERE id = $1',
            [stored.user_id]
        )

        const user = userResult.rows[0]

        const accessToken = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        )

        res.json({ accessToken })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

// POST /auth/logout
router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body

    if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' })
    }

    try {
        await pool.query(
            'DELETE FROM refresh_tokens WHERE token = $1',
            [refreshToken]
        )

        res.json({ message: 'Logged out successfully' })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

module.exports = router