# Codelab: MongoDB & REST APIs

In this codelab, we will build a simple REST API connected to a MongoDB database that we will read from and write to. We will also implement rudimentary security using JSON Web Tokens.

## The Setup

You will need to have NodeJS (https://nodejs.org), Git (https://git-scm.com/downloads), and MongoDB Server Community edition (https://www.mongodb.com/download-center/community) installed.

Now, you'll need to start your MongoDB server by using the `mongod` command in your terminal.

We will also need to clone this codelab's repository to have access to the basic front-end code that we will use to demonstrate that our API works. To do so, let's execute `git clone https://github.com/gdg-galway/gdg-mongodb-rest.git` and navigate to our new folder to run `npm install`.

Now that the setup is done, let's start coding!

## Creation of our REST API

Let's define a few things before starting:
- ExpressJS will be our web framework
- our API will use JSON as its default format
- we will use JSON Web Tokens to secure our API
- Auth tokens will be stored in a cookie or sent in the request's body or query string
- Our JWTs, once decoded, will contain the user's ID

Based on that, we'll need to import a few modules. First `body-parser` to parse incoming requests that should be sent in JSON format. And `cookie-parser` that will help us parse cookies in order for us to retrieve our Auth Token easily. We will also need `jsonwebtoken` to generate JWTs using our "secret" and decode/verify incoming tokens. And, of course, `express` to build our REST API and process requests.

```js
const API_SECRET = "ntZ8QsNSuaQcaAFG8Y5Fqh0vMI4LrHqm"
const PORT = 3000

const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')

const api = express()

// Static files will be served from our "static" folder
api.use(express.static(`${__dirname}/static/`))

// Parse URL-encoded requests
api.use(bodyParser.urlencoded({
	extended: true
}))

// Parse JSON requests
api.use(bodyParser.json())

// Parse cookies
api.use(cookieParser())

/** OUR ROUTES WILL GO THERE! **/

// Start API
api.listen(PORT, () => {
    console.log('API running on port', PORT)
})
```

## Security!

Our security will be simple but efficient. Before processing any requests, we will read the sender's cookies to find a token. If found, we will verify this token and retrieve the user's ID to finally add it to the Request object.

We will implement route-based security rules. Certain of our routes will be opened (like login & account creation flows) and others will be accessible only if certain criterias are met.

```js
api.use('/api/*', async (req, res, next) => {
    // Get auth token from querystring/body/cookie
    const token = req.query.token || req.body.token || req.cookies.token
    if(token) {
        try {
            // If token is verified successfully, user object will be stored in the request object at req.user
            req.user = await jwt.verify(token, API_SECRET)
        }
        catch(e) {
            // If not, we returned an error 401
            console.log(e.message)
            return res.status(401).json({
                code: 'INVALID_TOKEN',
                message: 'Invalid token'
            })
        }
    }
    next()
})
```

## User Authentication

Our users should be able to create an account and login. To do so, we'll need 2 new routes. Let's start with the account creation.

To be able to process requests and create an account, we'll add a few modules. `node-input-validator` will help with the validation of our incoming request parameters. And `shortid` will be used to generate our users' IDs.

We will follow best practices and won't store password in clear in our database, we will use `bcrypt` to hash/compare our passwords.

We will also need to register our users in our database so we'll initialize a MongoDB client to do so using the `mongodb` official module.

```js
const DB_URL = "mongodb://localhost:27017"
const DB_NAME = "myapi"

const bcrypt = require('bcrypt')
const Validator = require('node-input-validator')
const shortid = require('shortid')
const {MongoClient} = require('mongodb')

api.post('/api/v1/users', async (req, res) => {
    const validator = new Validator(req.body, {
        name: 'required|string|minLength:3|maxLength:24',
        email: 'required|email',
        password: 'required|string|minLength:8|maxLength:24'
    })
    // Validate request body
    const valid = await validator.check()
    if(valid) {
        const {name, email, password} = req.body
        // New MongoClient initialization
        const client = new MongoClient(DB_URL, { useNewUrlParser: true })
        try {
            // Connecting to database
            await client.connect()
            const db = client.db(DB_NAME)
            // Get users with the same email
            const users = await db.collection('users').find({ email })
            // Get users count
            const count = await users.count()
            // If there's no match we continue
            if(count === 0) {
                // Generate a short ID
                const id = shortid.generate()
                // Hash password with a salt 10
                const hash = await bcrypt.hash(password, 10)
                const created = Math.floor(Date.now() / 1000)
                // Insert our user in the users collection in our database
                await db.collection('users').insertOne({
                    id,
                    name,
                    email,
                    password: hash,
                    created
                })
                // Generate a JWT token containing our user's ID
                const token = await jwt.sign({ user_id: id }, API_SECRET, { expiresIn: '7d' })
                // Create a cookie containing our token
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
```

We can now continue with the login part of our user authentication routes.

```js
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
            // Find the user with the requested email
            const user = await db.collection('users').findOne({ email })
            // Compares the password sent with the encrypted password stored in our database
            const pwmatch = await bcrypt.compare(password, user.password)
            // If the passwords do not match we return an error
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
```

## User profiles

We will create a few routes to allow our users and admins to request profiles.

First, we'll give a way to our users to retrieve their own profile.

```js
api.get('/api/v1/users/me', async (req, res) => {
    // We make sure that the user is authenticated
    if(req.user) {
        const client = new MongoClient(DB_URL, { useNewUrlParser: true })
        try {
            await client.connect()
            const db = client.db(DB_NAME)
            // We find the user's profile based on the ID provided
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
```

Now let's create an admin route that allow an admin to access any user profile.

```js
api.get('/api/v1/users/:id', async (req, res) => {
    if(req.user) {
        // We make sure that the admin boolean contained in the decoded token is TRUE
        if(req.user.admin === true) {
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
```

## Let's test our code!

That's a lot of back-end code, let's test if everything is working properly.

First, we'll launch our API using the `node index.js` command.

I created a simple front-end for you to test your code. You should be able to access it at http://localhost:3000.

You can open the web console to see the responses coming from your API!

## Congratulations!

You have successfully completed this simple tutorial and created your own REST API using MongoDB, Express, JSON Web Tokens, bcrypt and more!

You can also check out an article I wrote on Medium about REST APIs: https://medium.com/creative-black-pug-studio/restful-apis-5b0944900e6a.

I hope you have enjoyed this codelab and I invite you to check our other tuts on https://github.com/gdg-galway.

You can also join our community and find us on the following platforms:
- Twitter: https://twitter.com/GDGgalway
- Meetup: https://www.meetup.com/Google-Developers-Group-in-Galway-Meetup/
- Discord: https://discord.gg/JWNVT4W
- Discourse: https://forum.gdg-galway.com