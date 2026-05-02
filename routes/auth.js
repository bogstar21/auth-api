const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const pool = require('../db')
const crypto = require('crypto')


const router = express.Router()
const SALT_ROUNDS = 10

const { Resend } = require('resend')
const resend = new Resend(process.env.RESEND_API_KEY)

function generateRefreshToken() {
    return crypto.randomBytes(64).toString('hex')
}

// POST /auth/register
router.post('/register', async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' })
    }

    try {
        const existing = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        )

        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Email already registered' })
        }

        const password_hash = await bcrypt.hash(password, SALT_ROUNDS)

        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
            [email, password_hash]
        )

        // Send welcome email
        try {
            const emailResult = await resend.emails.send({
                from: 'onboarding@resend.dev',
                to: email,
                subject: 'Welcome to Auth API',
                html: `
          <div style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:32px;border-radius:6px;">
            <h2 style="color:#00ff88;letter-spacing:3px;">ACCESS GRANTED</h2>
            <p style="color:#e0e0e0;margin-top:16px;">Your account has been created.</p>
            <p style="color:#555;margin-top:8px;">Email: ${email}</p>
            <p style="color:#555;margin-top:32px;font-size:12px;">auth-api — terminal v1.0</p>
          </div>
        `
            })
            console.log('Resend result:', JSON.stringify(emailResult))
        } catch (emailErr) {
            console.error('Resend error:', emailErr.message)
        }

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

// POST /auth/forgot-password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body

    if (!email) {
        return res.status(400).json({ error: 'Email is required' })
    }

    try {
        const result = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        )

        // Always respond the same — never reveal if email exists
        if (result.rows.length === 0) {
            return res.json({ message: 'If that email exists, a reset link has been sent' })
        }

        const user = result.rows[0]

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex')
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000) // 1 hour

        await pool.query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, resetToken, expiresAt]
        )

        const resetUrl = `${process.env.APP_URL}/reset-password.html?token=${resetToken}`

        await resend.emails.send({
            from: 'onboarding@resend.dev',
            to: email,
            subject: 'Password Reset Request',
            html: `
        <div style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:32px;border-radius:6px;">
          <h2 style="color:#00ff88;letter-spacing:3px;">RESET REQUEST</h2>
          <p style="color:#e0e0e0;margin-top:16px;">A password reset was requested for this account.</p>
          <p style="color:#555;margin-top:8px;">This link expires in 1 hour.</p>
          <a href="${resetUrl}" style="display:inline-block;margin-top:24px;padding:12px 24px;border:1px solid #00ff88;color:#00ff88;text-decoration:none;letter-spacing:2px;">
            [ RESET PASSWORD ]
          </a>
          <p style="color:#333;margin-top:32px;font-size:12px;">If you didn't request this, ignore this email.</p>
        </div>
      `
        })

        res.json({ message: 'If that email exists, a reset link has been sent' })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

// POST /auth/reset-password
router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body

    if (!token || !password) {
        return res.status(400).json({ error: 'Token and password are required' })
    }

    try {
        const result = await pool.query(
            'SELECT * FROM password_reset_tokens WHERE token = $1',
            [token]
        )

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset token' })
        }

        const resetToken = result.rows[0]

        // Check if already used
        if (resetToken.used) {
            return res.status(400).json({ error: 'Reset token already used' })
        }

        // Check if expired
        if (new Date() > new Date(resetToken.expires_at)) {
            return res.status(400).json({ error: 'Reset token expired' })
        }

        // Hash new password
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS)

        // Update password
        await pool.query(
            'UPDATE users SET password_hash = $1 WHERE id = $2',
            [password_hash, resetToken.user_id]
        )

        // Mark token as used
        await pool.query(
            'UPDATE password_reset_tokens SET used = TRUE WHERE id = $1',
            [resetToken.id]
        )

        res.json({ message: 'Password updated successfully' })

    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Internal server error' })
    }
})

module.exports = router