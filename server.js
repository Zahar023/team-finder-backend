require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Debug: Проверка переменных окружения
console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'exists' : 'missing');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'exists' : 'missing');
console.log('PORT:', process.env.PORT);

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Проверка подключения к БД
pool.query('SELECT NOW()')
  .then(res => console.log('Подключено к PostgreSQL:', res.rows[0].now))
  .catch(err => console.error('Ошибка подключения к PostgreSQL:', err));

// Регистрация пользователя
app.post('/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, name]
    );
    const token = jwt.sign({ userId: rows[0].id }, process.env.JWT_SECRET);
    res.status(201).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка регистрации' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // 1. Находим пользователя в БД
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!rows[0]) return res.status(401).json({ error: 'Пользователь не найден' });

    // 2. Проверяем пароль
    const isValid = await bcrypt.compare(password, rows[0].password_hash);
    if (!isValid) return res.status(401).json({ error: 'Неверный пароль' });

    // 3. Генерируем токен
    const token = jwt.sign({ userId: rows[0].id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // "Bearer TOKEN"
  if (!token) return res.status(401).json({ error: 'Токен отсутствует' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Добавляем ID пользователя в запрос
    next();
  } catch (err) {
    res.status(401).json({ error: 'Неверный токен' });
  }
};

// Пример защищенного роута
app.get('/auth/profile', authenticate, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
  res.json(rows[0]);
});

// Запуск сервера
const PORT = process.env.PORT || 10000; 

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});