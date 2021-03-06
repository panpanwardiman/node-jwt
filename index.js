require('dotenv').config()

const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

const app = express()

const {login, refresh} = require('./authentication')

app.use(bodyParser.json())
app.use(cookieParser())

app.post('/login', login)
app.post('/refresh', refresh)
app.post('/test', (req, res, next) => {
    console.log(`request: ${req.body.test}`)
    next()
})

const port = process.env.PORT || 4000
app.listen(port, () => {
    console.log(`Server is running on port: ${port}`)
})

