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


// Получение или создание чата с пользователем
app.post('/chats', authenticate, async (req, res) => {
  try {
    const { partnerId } = req.body;
    
    // Проверка partnerId
    const partnerIdNum = Number(partnerId);
    if (isNaN(partnerIdNum)) {
      return res.status(400).json({ error: 'Неверный ID партнера' });
    }

    // Проверяем существование чата
    const existingChat = await pool.query(
      `SELECT id, user1_id, user2_id, created_at FROM chats 
       WHERE (user1_id = $1 AND user2_id = $2)
          OR (user1_id = $2 AND user2_id = $1)`,
      [req.userId, partnerIdNum]
    );

    // Если чат существует - возвращаем его
    if (existingChat.rows[0]) {
      const chat = existingChat.rows[0];
      return res.json({
        id: Number(chat.id),
        user1_id: Number(chat.user1_id),
        user2_id: Number(chat.user2_id),
        created_at: chat.created_at
      });
    }

    // Создаем новый чат (упорядочиваем ID для уникальности)
    const [user1, user2] = req.userId < partnerIdNum 
      ? [req.userId, partnerIdNum] 
      : [partnerIdNum, req.userId];

    const { rows } = await pool.query(
      `INSERT INTO chats (user1_id, user2_id)
       VALUES ($1, $2) 
       RETURNING id, user1_id, user2_id, created_at`,
      [user1, user2]
    );

    const newChat = rows[0];
    res.status(201).json({
      id: Number(newChat.id),
      user1_id: Number(newChat.user1_id),
      user2_id: Number(newChat.user2_id),
      created_at: newChat.created_at
    });
  } catch (err) {
    console.error('Ошибка создания чата:', err);
    res.status(500).json({ error: 'Ошибка создания чата' });
  }
});

// Получение сообщений чата
app.get('/chats/:chatId/messages', authenticate, async (req, res) => {
  try {
    // Проверка доступа
    const accessCheck = await pool.query(
      `SELECT 1 FROM chats 
       WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
      [req.params.chatId, req.userId]
    );
    if (!accessCheck.rows[0]) return res.status(403).json({ error: 'Нет доступа к чату' });

    const { rows } = await pool.query(
      `SELECT m.*, u.name as sender_name
       FROM messages m
       JOIN users u ON m.sender_id = u.id
       WHERE chat_id = $1
       ORDER BY created_at`,
      [req.params.chatId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка получения сообщений' });
  }
});

// Отправка сообщения
app.post('/chats/:chatId/messages', authenticate, async (req, res) => {
  const { content } = req.body;
  try {
    // Проверка доступа
    const accessCheck = await pool.query(
      `SELECT 1 FROM chats 
       WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
      [req.params.chatId, req.userId]
    );
    if (!accessCheck.rows[0]) return res.status(403).json({ error: 'Нет доступа к чату' });

    const { rows } = await pool.query(
      `INSERT INTO messages (chat_id, sender_id, content)
       VALUES ($1, $2, $3) RETURNING *`,
      [req.params.chatId, req.userId, content]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка отправки сообщения' });
  }
});

// Получение списка пользователей
app.get('/users', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, name, email FROM users WHERE id != $1',
      [req.userId]
    );
    // Убедитесь, что id возвращается как число
    res.json(rows.map(row => ({
      id: Number(row.id),
      name: row.name,
      email: row.email
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка получения пользователей' });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 10000; 

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});