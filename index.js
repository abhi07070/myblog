// Import required packages
const User = require('./models/User');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' })
const fs = require('fs');
const Post = require('./models/Post')
// Load environment variables from .env file
dotenv.config();

// Set up port and MongoDB connection string
const port = process.env.PORT || 4040;
const mongoUrl = process.env.MONGO_URL;
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET;
const clientUrl = process.env.CLIENT_URL;
// Connect to MongoDB using Mongoose
mongoose.set('strictQuery', false);
mongoose.connect(mongoUrl)
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1);
    });

// Create Express app instance
const app = express();

// Set up middleware
app.use(cors({
    credentials: true,
    origin: clientUrl
}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

// Define route for handling POST requests to /register
app.post('/register', async (req, res) => {

    const { username, password } = req.body;

    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
        const userDoc = await User.create({
            username: username,
            password: hashedPassword
        });
        res.json(userDoc);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create user.' });
    }

});

app.post('/login', async (req, res) => {

    const { username, password } = req.body;
    const userDoc = await User.findOne({ username });

    if (!userDoc) {
        return res.status(400).json({ error: 'User not found' });
    }

    const passOk = bcrypt.compareSync(password, userDoc.password);

    if (!passOk) {
        return res.status(400).json({ error: 'Wrong credentials' });
    }

    jwt.sign({ username, id: userDoc._id }, jwtSecret, {}, (err, token) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to create token' });
        }
        res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true }).json({
            id: userDoc._id,
            username
        });
    });

});

app.get('/profile', (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        // No token found in cookie
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    jwt.verify(token, jwtSecret, {}, (err, info) => {
        if (err) {
            // Invalid token
            res.clearCookie('token').status(401).json({ error: 'Unauthorized' });
            return;
        }
        res.json(info);
    });
});

app.post('/logout', (req, res) => {
    res.clearCookie('token', { sameSite: 'none', secure: true }).json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, newPath);

    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
        if (err) {
            res.clearCookie('token').status(401).json({ error: 'Unauthorized' });
            return;
        }

        const { title, summary, content } = req.body;
        const postDoc = await Post.create({
            title,
            summary,
            content,
            cover: newPath,
            author: info.id,
        });

        res.json(postDoc)
    });

})

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
    let newPath = null;
    if (req.file) {
        const { originalname, path } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        const newPath = path + '.' + ext;
        fs.renameSync(path, newPath);
    }

    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
        if (err) {
            res.clearCookie('token').status(401).json({ error: 'Unauthorized' });
            return;
        }

        const { id, title, summary, content } = req.body;
        const postDoc = await Post.findById(id);
        const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
        if (!isAuthor) {
            res.status(400).json({ error: 'you are not the author' })
            return;
        }

        await postDoc.update({
            title,
            summary,
            content,
            cover: newPath ? newPath : postDoc.cover,
        });

        res.json(postDoc)
    });

})

app.delete('/post/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, info) => {
      if (err) {
        res.clearCookie('token').status(401).json({ error: 'Unauthorized' });
        return;
      }
      const postDoc = await Post.findById(id);
      if (!postDoc) {
        res.status(404).json({ error: 'Post not found' });
        return;
      }
      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) {
        res.status(400).json({ error: 'you are not the author' })
        return;
      }
      await postDoc.delete();
      res.json({ message: 'Post deleted' });
    });
  });

app.get('/post', async (req, res) => {
    const posts = await Post.find()
        .populate('author', ['username'])
        .sort({ createdAt: -1 })
        .limit(20);
    res.json(posts);
})

app.get('/post/:id', async (req, res) => {
    const { id } = req.params;
    const postDoc = await Post.findById(id)
        .populate('author', ['username']);
    res.json(postDoc);
})

// Start Express app listening on specified port
app.listen(port, () => {
    console.log(`Listening at port ${port}`);
});
