const jwt = require('jsonwebtoken')

exports.verify = (req, res, next) => {
    let accessToken =  req.cookies.jwt

    if (!accessToken) { 
        return res.status(403).send()
    }

    let payload 
    try {
        payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET)
        next()
    } catch (e) {
        return res.status(401).send()
    }
}