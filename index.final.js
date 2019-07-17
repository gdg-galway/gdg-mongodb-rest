const API_SECRET = "ntZ8QsNSuaQcaAFG8Y5Fqh0vMI4LrHqm"
const DB_URL = "mongodb://localhost:27017"
const DB_NAME = "myapi"
const PORT = 3000

const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const Validator = require('node-input-validator')
const shortid = require('shortid')
const {MongoClient} = require('mongodb')

const api = express()

api.use(express.static(`${__dirname}/static/`))

api.use(bodyParser.urlencoded({
	extended: true
}))

api.use(bodyParser.json())

api.use(cookieParser())

api.use('/api/*', async (req, res, next) => {
    const token = req.query.token || req.body.token || req.cookies.token
    if(token) {
        try {
            req.user = await jwt.verify(token, API_SECRET)
        }
        catch(e) {
            console.log(e.message)
            return res.status(401).json({
                code: 'INVALID_TOKEN',
                message: 'Invalid token'
            })
        }
    }
    next()
})

api.post('/api/v1/auth', async (req, res) => {
    const validator = new Validator(req.body, {
        email: 'required|email',
        password: 'required|string|minLength:8|maxLength:24'
    })
    const valid = await validator.check()
    if(valid) {
        const {email, password} = req.body
        const client = new MongoClient(DB_URL, { useNewUrlParser: true })
        try {
            await client.connect()
            const db = client.db(DB_NAME)
            const user = await db.collection('users').findOne({ email })
            const pwmatch = await bcrypt.compare(password, user.password)
            if(!pwmatch) throw new Error()
            const token = await jwt.sign({ user_id: user.id }, API_SECRET, { expiresIn: '7d' })
            res.cookie('token', token, {
                expires: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
            })
            res.json({
                id: user.id,
                name: user.name,
                email,
                created: user.created,
                token
            })
        }
        catch(e) {
            res.status(400).json({
                code: 'INVALID_PARAMETERS',
                message: 'Your credentials are not valid'
            })
        }
        client.close()
    }
    else {
        res.status(400).json({
            code: 'INVALID_PARAMETERS',
            message: 'At least one field is invalid. Try again.'
        })
    }
})

api.get('/api/v1/users/me', async (req, res) => {
    if(req.user) {
        const client = new MongoClient(DB_URL, { useNewUrlParser: true })
        try {
            await client.connect()
            const db = client.db(DB_NAME)
            const user = await db.collection('users').findOne({ id: req.user.user_id })
            res.json({
                id: user.id,
                name: user.name,
                email: user.email,
                created: user.created,
            })
        }
        catch(e) {
            console.log(e.message)
            res.status(404).json({
                code: 'NOT_FOUND',
                message: 'User not found'
            })
        }
        client.close()
    }
    else {
        res.status(401).json({
            code: 'UNAUTHENTICATED',
            message: 'You need to be logged in.'
        })
    }
})

api.get('/api/v1/users/:id', async (req, res) => {
    if(req.user) {
        if(req.user.admin) {
            const client = new MongoClient(DB_URL, { useNewUrlParser: true })
            try {
                await client.connect()
                const db = client.db(DB_NAME)
                const user = await db.collection('users').findOne({ id: req.params.id })
                res.json({
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    created: user.created,
                })
            }
            catch(e) {
                console.log(e.message)
                res.status(404).json({
                    code: 'NOT_FOUND',
                    message: 'User not found'
                })
            }
            client.close()
        }
        else {
            res.status(403).json({
                code: 'FORBIDDEN',
                message: 'You do not have access to this resource.'
            })
        }
    }
    else {
        res.status(401).json({
            code: 'UNAUTHENTICATED',
            message: 'You need to be logged in.'
        })
    }
})

api.post('/api/v1/users', async (req, res) => {
    const validator = new Validator(req.body, {
        name: 'required|string|minLength:3|maxLength:24',
        email: 'required|email',
        password: 'required|string|minLength:8|maxLength:24'
    })
    const valid = await validator.check()
    if(valid) {
        const {name, email, password} = req.body
        const client = new MongoClient(DB_URL, { useNewUrlParser: true })
        try {
            await client.connect()
            const db = client.db(DB_NAME)
            const users = await db.collection('users').find({ email })
            const count = await users.count()
            if(count === 0) {
                const id = shortid.generate()
                const hash = await bcrypt.hash(password, 10)
                const created = Math.floor(Date.now() / 1000)
                await db.collection('users').insertOne({
                    id,
                    name,
                    email,
                    password: hash,
                    created
                })
                const token = await jwt.sign({ user_id: id }, API_SECRET, { expiresIn: '7d' })
                res.cookie('token', token, {
                    expires: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
                })
                res.status(201).json({
                    id,
                    name,
                    email,
                    created,
                    token
                })
            }
            else {
                res.status(409).json({
                    code: 'ALREADY_EXISTS',
                    message: 'An account with this email is already registered'
                })
            }
        }
        catch(e) {
            console.log(e.message)
            res.status(404).json({
                code: 'NOT_FOUND',
                message: 'User not found'
            })
        }
        client.close()
    }
    else {
        console.log(req.body)
        res.status(400).json({
            code: 'INVALID_PARAMETERS',
            message: 'At least one field is invalid. Try again.'
        })
    }
})

api.listen(PORT, () => {
    console.log('API running on port', PORT)
})