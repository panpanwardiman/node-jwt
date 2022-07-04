const jwt = require('jsonwebtoken')

let users = {
    john: {password: "passwordJohn"},
    mary: {password: "passwordMary"}
} 

exports.login = (req, res, next) => {
    
    // let username = "john"
    // let password = "passwordJohn"

    let username = req.body.username
    let password = req.body.password

    if (!username || !password || users[username].password !== password) {
        console.log(password)
        return res.status(401).send()
    }

    let payload = {username: username}

    let accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: process.env.ACCESS_TOKEN_LIFE
    })

    let refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
        algorithm: "HS256",
        expiresIn: process.env.REFRESH_TOKEN_LIFE
    })

    users[username].refreshToken = refreshToken

    res.cookie("jwt", accessToken)
    res.send()
}

exports.refresh = (req, res, next) => {
    let accessToken = req.cookies.jwt

    if (!accessToken) {
        return res.status(403).send()
    }

    let payload
    try{
        payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET)
     }
    catch(e){
        return res.status(401).send()
    }

    let refreshToken = users[payload.username].refreshToken

    try {
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    } catch (error) {
        return res.status(401).send()
    }

    let newToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
        algorithm: 'HS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
    })

    res.cookie("jwt", newToken)
    res.send()
}

