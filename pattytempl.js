/**
 * @name: pattytempl
 * @author: Wellington W. F. Sarmento and Patricia de Sousa Paula
 * @version: 1.0.0
 * @license: GPL-3.0
 * @description:
 * This script generates a base Express application template.
 * It creates the following directories:
 * - models
 * - routes
 * - middleware
 * - views
 * 
 */

const fs = require('fs');
const path = require('path');


// recivie argments of user to create a new project
const projectName = process.argv[2];

// Base directory path
const baseDir = path.join(__dirname, projectName);

// Create project directory
fs.mkdirSync(baseDir, { recursive: true });


// Directories to be created
const directories = [
    'models',
    'routes',
    'middleware',
    'views'
];

// Create each directory
directories.forEach(directory => {
    fs.mkdirSync(path.join(baseDir, directory), { recursive: true });
});

// Base content for app.js
const appContent = `
const express = require('express');
const path = require('path');
const app = express();

app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

app.use('/', require('./routes/documentRoutes'));
app.use('/', require('./routes/userRoutes'));

module.exports = app;
`;

// Base content for server.js
const serverContent = `
const app = require('./app');
const port = process.env.PORT || 3000;

app.listen(port, () => console.log(\`Server is up on port \${port}\`));
`;

// Base content for userModel.js
const userModelContent = `
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
});

UserSchema.pre('save', async function (next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

UserSchema.methods.generateAuthToken = async function() {
    const user = this;
    const token = jwt.sign({_id: user._id}, process.env.JWT_KEY);
    user.tokens = user.tokens.concat({token});
    await user.save();
    return token;
}

UserSchema.statics.findByCredentials = async (username, password) => {
    const user = await User.findOne({username} );
    if (!user) {
        throw new Error({ error: 'Invalid login credentials' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
        throw new Error({ error: 'Invalid login credentials' });
    }
    return user;
}

const User = mongoose.model('User', UserSchema);

module.exports = User;
`;

// Base content for userRoutes.js
const userRoutesContent = `
const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.post('/users', async (req, res) => {
    try {
        const user = new User(req.body);
        await user.save();
        const token = await user.generateAuthToken();
        res.status(201).send({ user, token });
    } catch (error) {
        res.status(400).send(error);
    }
});

router.post('/users/login', async(req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findByCredentials(username, password);
        if (!user) {
            return res.status(401).send({error: 'Login failed! Check authentication credentials'});
        }
        const token = await user.generateAuthToken();
        res.send({ user, token });
    } catch (error) {
        res.status(400).send(error);
    }
});

module.exports = router;
`;

// Base content for auth.js
const authContent = `
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async(req, res, next) => {
    const token = req.header('Authorization').replace('Bearer ', '');
    const data = jwt.verify(token, process.env.JWT_KEY);
    try {
        const user = await User.findOne({ _id: data._id, 'tokens.token': token });
        if (!user) {
            throw new Error();
        }
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).send({ error: 'Not authorized to access this resource' });
    }
}

module.exports = auth;
`;

// Base content for package.json
const packageContent = `
{
    "name": "${baseDir}",
    "version": "1.0.0",
    "description": "",
    "main": "server.js",
    "scripts": {
        "start": "node server.js"
    },
    "keywords": [],
    "author": "",
    "license": "GPL-3.0-or-later",
    "dependencies": {
        "express": "^4.17.1",
        "mongoose": "^5.13.7",
        "pug": "^3.0.2",
        "jsonwebtoken": "^8.5.1",
        "bcryptjs": "^2.4.3"
    }
}
`;

//create .env file
fs.writeFileSync(path.join(baseDir, '.env'), '');

//create documentModel.js
const documentModelContent = `
// models/DocumentModel.js

const mongoose = require('mongoose');

const DocumentModel = {};

DocumentModel.insert = function(collectionName, newDocument, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    new Model(newDocument).save(callback);
}

DocumentModel.deleteOne = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.deleteOne(condition, callback);
}

DocumentModel.listOne = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.findOne(condition, callback);
}

DocumentModel.listAll = function(collectionName, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find({}, callback);
}

DocumentModel.editOne = function(collectionName, condition, newDocument, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.findOneAndUpdate(condition, newDocument, callback);
}

DocumentModel.deleteMany = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.deleteMany(condition, callback);
}

DocumentModel.listMany = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find(condition, callback);
}

DocumentModel.search = function(collectionName, query, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find(query, callback);
}

module.exports = DocumentModel;
`;

//create documentRoutes.js
const documentRoutesContent = `
const mongoose = require('mongoose');

const DocumentModel = {};

DocumentModel.insert = function(collectionName, newDocument, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    new Model(newDocument).save(callback);
}

DocumentModel.deleteOne = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.deleteOne(condition, callback);
}

DocumentModel.listOne = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.findOne(condition, callback);
}

DocumentModel.listAll = function(collectionName, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find({}, callback);
}

DocumentModel.editOne = function(collectionName, condition, newDocument, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.findOneAndUpdate(condition, newDocument, callback);
}

DocumentModel.deleteMany = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.deleteMany(condition, callback);
}

DocumentModel.listMany = function(collectionName, condition, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find(condition, callback);
}

DocumentModel.search = function(collectionName, query, callback){
    const Model = mongoose.model(collectionName, new mongoose.Schema({}, {strict: false}));
    Model.find(query, callback);
}

module.exports = DocumentModel;
`;

// Base content for userModel.js
const userModelContent = `
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
});

UserSchema.pre('save', async function (next) {
    // Hash the password before saving the user model
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

UserSchema.methods.generateAuthToken = async function() {
    // Generate an auth token for the user
    const user = this;
    const token = jwt.sign({_id: user._id}, process.env.JWT_KEY);
    user.tokens = user.tokens.concat({token});
    await user.save();
    return token;
}

UserSchema.statics.findByCredentials = async (username, password) => {
    // Search for a user by username and password.
    const user = await User.findOne({username} );
    if (!user) {
        throw new Error({ error: 'Invalid login credentials' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
        throw new Error({ error: 'Invalid login credentials' });
    }
    return user;
}

const User = mongoose.model('User', UserSchema);

module.exports = User;
`;



// Write the base files
fs.writeFileSync(path.join(baseDir, 'app.js'), appContent);
fs.writeFileSync(path.join(baseDir, 'server.js'), serverContent);
fs.writeFileSync(path.join(baseDir, 'package.json'), packageContent);
fs.writeFileSync(path.join(baseDir, 'models', 'UserModel.js'), userModelContent);
fs.writeFileSync(path.join(baseDir, 'routes', 'userRoutes.js'), userRoutesContent);
fs.writeFileSync(path.join(baseDir, 'middleware', 'auth.js'), authContent);
fs.writeFileSync(path.join(baseDir, 'models', 'DocumentModel.js'), documentModelContent);
fs.writeFileSync(path.join(baseDir, 'routes', 'documentRoutes.js'), documentRoutesContent);


console.log('Your base Express application template has been generated.');
console.log('Run npm install to install dependencies.');
console.log('Run npm start to start the server.');
