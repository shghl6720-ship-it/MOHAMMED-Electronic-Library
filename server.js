const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'your_secret_key_123';

// الاتصال بقاعدة البيانات
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'mohammed_library'
});

// 1. مسار تسجيل حساب جديد
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ error: 'يرجى ملء جميع الحقول المطلوبة' });
    }

    try {
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'البريد الإلكتروني مسجل بالفعل' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
            [fullName, email, hashedPassword]
        );

        const token = jwt.sign({ id: result.insertId, email }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            token,
            user: { id: result.insertId, fullName, email }
        });
    } catch (err) {
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// 2. مسار تسجيل الدخول
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'البريد الإلكتروني أو كلمة السر غير صحيحة' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'البريد الإلكتروني أو كلمة السر غير صحيحة' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'تم تسجيل الدخول بنجاح',
            token,
            user: { id: user.id, fullName: user.full_name, email: user.email }
        });
    } catch (err) {
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
