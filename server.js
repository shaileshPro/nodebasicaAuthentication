const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('./config.json')

mongoose.connect('mongodb://localhost:27017/user-Auth', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	//useCreateIndex: true
}, err => {
	if(err) throw err;
	console.log('Connected to MongoDB!!!')
 })

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/updateUser', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body
	const { secret } = config;

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwt.verify(token, secret)
                console.log(user)
		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' ,msg: user.username + " password sucessfully changed"})
	} catch (error) {
		
		res.json({ status: 'error', error: error.message })
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const { secret } = config;
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			secret,
			{
				expiresIn: "90s",
			  }
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})

app.post('/api/register', async (req, res) => {
	const { username, password: plainTextPassword } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
		throw error
	}

	res.json({ status: 'ok' })
})


app.get('/api/listUser', async (req, res) => {
	const { username, password: plainTextPassword } = req.body
	let user 

	try {
		 user = await User.find({}, {_id:0, username : 1})
		if(user.length==0)
			  throw error;
			  
	} catch (error) {
		return res.json({
			status: 'error',
			statuscode:404,
			error: 'no record found'
		})
	}

	res.json({ status: 'ok' ,User:user})
})

app.listen(7800, () => {
	console.log('Server up at 7800')
})
