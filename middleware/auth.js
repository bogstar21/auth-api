const jwt = require('jsonwebtoken')

function authenticateToken(req, res, next) {
    // Token comes in the header as: "Bearer eyJhbG..."
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ error: 'Access token required' })
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET)
        req.user = payload // attach user info to the request
        next()
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' })
    }
}

module.exports = authenticateToken