const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'anon_lounge_' + crypto.randomBytes(16).toString('hex');

// ── DB 초기화 ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        gender TEXT NOT NULL,
        birth_year INTEGER NOT NULL,
        photo TEXT,
        height INTEGER,
        body_type TEXT,
        job TEXT,
        personality TEXT DEFAULT '[]',
        hobbies TEXT DEFAULT '[]',
        bio TEXT DEFAULT '',
        phone TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        coins INTEGER DEFAULT 10,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      );
      CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        gender TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        post_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        gender TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      );
      CREATE TABLE IF NOT EXISTS likes (
        id TEXT PRIMARY KEY,
        from_user_id TEXT NOT NULL,
        to_user_id TEXT NOT NULL,
        post_id TEXT NOT NULL,
        status TEXT DEFAULT 'sent',
        sender_phone_revealed INTEGER DEFAULT 0,
        receiver_phone_revealed INTEGER DEFAULT 0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        UNIQUE(from_user_id, to_user_id)
      );
    `);
    console.log('✅ DB 초기화 완료');
  } finally {
    client.release();
  }
}

// ── 미들웨어 ────────────────────────────────────────────────
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const COST_HEART = 9;
const COST_VIEW  = 4;
const COST_PHONE = 120;
const CURRENT_YEAR = new Date().getFullYear();

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '로그인이 필요해요' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: '세션이 만료됐어요. 다시 로그인해주세요' }); }
}

const uid = () => crypto.randomBytes(8).toString('hex');

function fmtUser(u, withPhone = false) {
  if (!u) return null;
  return {
    id: u.id, gender: u.gender, birthYear: u.birth_year,
    photo: u.photo, height: u.height, bodyType: u.body_type,
    job: u.job,
    personality: typeof u.personality === 'string' ? JSON.parse(u.personality || '[]') : (u.personality || []),
    hobbies: typeof u.hobbies === 'string' ? JSON.parse(u.hobbies || '[]') : (u.hobbies || []),
    bio: u.bio,
    coins: u.coins, phone: withPhone ? u.phone : undefined,
  };
}

// ── 회원가입 / 로그인 ────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { gender, birthYear, photo, height, bodyType, job, personality, hobbies, bio, phone, password } = req.body;
  if (!gender || !birthYear || !phone || !password)
    return res.status(400).json({ error: '필수 정보를 모두 입력해주세요' });
  if (parseInt(birthYear) > CURRENT_YEAR - 19)
    return res.status(400).json({ error: '만 19세 이상만 가입 가능해요' });

  try {
    const existing = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: '이미 가입된 전화번호예요' });

    const id = uid();
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(
      `INSERT INTO users (id,gender,birth_year,photo,height,body_type,job,personality,hobbies,bio,phone,password,coins)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,10)`,
      [id, gender, parseInt(birthYear), photo||null, height||null, bodyType||null, job||null,
       JSON.stringify(personality||[]), JSON.stringify(hobbies||[]), bio||'', phone, hash]
    );
    const token = jwt.sign({ id }, SECRET, { expiresIn: '30d' });
    const u = (await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
    res.json({ token, user: fmtUser(u) });
  } catch (e) { res.status(500).json({ error: '가입 중 오류: ' + e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: '정보를 입력해주세요' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE phone=$1', [phone]);
    const u = rows[0];
    if (!u || !bcrypt.compareSync(password, u.password))
      return res.status(401).json({ error: '전화번호 또는 비밀번호가 틀렸어요' });
    const token = jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
    res.json({ token, user: fmtUser(u) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: '없음' });
    res.json(fmtUser(rows[0], true));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 게시글 ──────────────────────────────────────────────────
app.get('/api/posts', auth, async (req, res) => {
  try {
    const { gender } = req.query;
    let q = 'SELECT * FROM posts';
    const p = [];
    if (gender && ['M','F'].includes(gender)) { q += ' WHERE gender=$1'; p.push(gender); }
    q += ' ORDER BY created_at DESC LIMIT 60';
    const posts = (await pool.query(q, p)).rows;

    const result = await Promise.all(posts.map(async post => {
      const cc = (await pool.query('SELECT COUNT(*) c FROM comments WHERE post_id=$1', [post.id])).rows[0].c;
      const hc = (await pool.query('SELECT COUNT(*) c FROM likes WHERE post_id=$1', [post.id])).rows[0].c;
      const il = (await pool.query('SELECT id FROM likes WHERE from_user_id=$1 AND post_id=$2', [req.user.id, post.id])).rows[0];
      return { ...post, commentCount: parseInt(cc), heartCount: parseInt(hc), iLiked: !!il };
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts', auth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length < 1 || content.length > 500)
    return res.status(400).json({ error: '내용을 확인해주세요 (1~500자)' });
  try {
    const u = (await pool.query('SELECT gender FROM users WHERE id=$1', [req.user.id])).rows[0];
    const id = uid();
    await pool.query('INSERT INTO posts (id,user_id,gender,content) VALUES ($1,$2,$3,$4)', [id, req.user.id, u.gender, content.trim()]);
    const post = (await pool.query('SELECT * FROM posts WHERE id=$1', [id])).rows[0];
    res.json({ ...post, commentCount: 0, heartCount: 0, iLiked: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM comments WHERE post_id=$1 ORDER BY created_at ASC', [req.params.id]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.length > 300) return res.status(400).json({ error: '댓글 내용 오류' });
  try {
    const u = (await pool.query('SELECT gender FROM users WHERE id=$1', [req.user.id])).rows[0];
    const id = uid();
    await pool.query('INSERT INTO comments (id,post_id,user_id,gender,content) VALUES ($1,$2,$3,$4,$5)', [id, req.params.id, req.user.id, u.gender, content.trim()]);
    res.json((await pool.query('SELECT * FROM comments WHERE id=$1', [id])).rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 하트 / 호감 ─────────────────────────────────────────────
app.post('/api/likes', auth, async (req, res) => {
  const { postId } = req.body;
  try {
    const post = (await pool.query('SELECT * FROM posts WHERE id=$1', [postId])).rows[0];
    if (!post) return res.status(404).json({ error: '게시글 없음' });
    if (post.user_id === req.user.id) return res.status(400).json({ error: '본인 글에는 불가해요' });
    const already = (await pool.query('SELECT id FROM likes WHERE from_user_id=$1 AND to_user_id=$2', [req.user.id, post.user_id])).rows[0];
    if (already) return res.status(400).json({ error: '이미 하트를 보낸 분이에요' });
    const u = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0];
    if (u.coins < COST_HEART) return res.status(400).json({ error: `코인 부족 (필요: ${COST_HEART}코인)` });

    const id = uid();
    await pool.query('INSERT INTO likes (id,from_user_id,to_user_id,post_id) VALUES ($1,$2,$3,$4)', [id, req.user.id, post.user_id, postId]);
    await pool.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [COST_HEART, req.user.id]);
    const updated = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0];
    const like = (await pool.query('SELECT * FROM likes WHERE id=$1', [id])).rows[0];
    res.json({ like, coins: updated.coins });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: '이미 하트를 보낸 분이에요' });
    res.status(500).json({ error: e.message });
  }
});

// 프로필 열람 (받은 사람이 결제)
app.put('/api/likes/:id/view', auth, async (req, res) => {
  try {
    const like = (await pool.query('SELECT * FROM likes WHERE id=$1', [req.params.id])).rows[0];
    if (!like) return res.status(404).json({ error: '없음' });
    if (like.to_user_id !== req.user.id) return res.status(403).json({ error: '권한 없음' });
    if (like.status === 'viewed') {
      const sender = (await pool.query('SELECT * FROM users WHERE id=$1', [like.from_user_id])).rows[0];
      const coins = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0].coins;
      return res.json({ already: true, sender: fmtUser(sender), coins });
    }
    const u = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0];
    if (u.coins < COST_VIEW) return res.status(400).json({ error: `코인 부족 (필요: ${COST_VIEW}코인)` });

    await pool.query("UPDATE likes SET status='viewed' WHERE id=$1", [req.params.id]);
    await pool.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [COST_VIEW, req.user.id]);
    const sender = (await pool.query('SELECT * FROM users WHERE id=$1', [like.from_user_id])).rows[0];
    const coins = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0].coins;
    res.json({ sender: fmtUser(sender), coins });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 번호 오픈
app.put('/api/likes/:id/reveal-phone', auth, async (req, res) => {
  try {
    const like = (await pool.query('SELECT * FROM likes WHERE id=$1', [req.params.id])).rows[0];
    if (!like) return res.status(404).json({ error: '없음' });
    if (like.from_user_id !== req.user.id && like.to_user_id !== req.user.id) return res.status(403).json({ error: '권한 없음' });
    if (like.status !== 'viewed') return res.status(400).json({ error: '프로필 열람 후 가능해요' });

    const isSender = like.from_user_id === req.user.id;
    const alreadyRevealed = isSender ? like.sender_phone_revealed : like.receiver_phone_revealed;
    if (alreadyRevealed) return res.status(400).json({ error: '이미 공개했어요' });

    const u = (await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id])).rows[0];
    if (u.coins < COST_PHONE) return res.status(400).json({ error: `코인 부족 (필요: ${COST_PHONE}코인)` });

    const field = isSender ? 'sender_phone_revealed' : 'receiver_phone_revealed';
    await pool.query(`UPDATE likes SET ${field}=1 WHERE id=$1`, [req.params.id]);
    await pool.query('UPDATE users SET coins=coins-$1 WHERE id=$2', [COST_PHONE, req.user.id]);
    const coins = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0].coins;
    res.json({ myPhone: u.phone, coins });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 받은/보낸 하트 목록
app.get('/api/likes/received', auth, async (req, res) => {
  try {
    const likes = (await pool.query('SELECT * FROM likes WHERE to_user_id=$1 ORDER BY created_at DESC', [req.user.id])).rows;
    const result = await Promise.all(likes.map(async l => {
      const sender = (await pool.query('SELECT * FROM users WHERE id=$1', [l.from_user_id])).rows[0];
      const post = (await pool.query('SELECT content FROM posts WHERE id=$1', [l.post_id])).rows[0];
      return { ...l,
        senderGender: sender?.gender,
        senderProfile: l.status === 'viewed' ? fmtUser(sender) : null,
        senderPhone: l.receiver_phone_revealed ? sender?.phone : null,
        postContent: post?.content || '' };
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/likes/sent', auth, async (req, res) => {
  try {
    const likes = (await pool.query('SELECT * FROM likes WHERE from_user_id=$1 ORDER BY created_at DESC', [req.user.id])).rows;
    const result = await Promise.all(likes.map(async l => {
      const recv = (await pool.query('SELECT * FROM users WHERE id=$1', [l.to_user_id])).rows[0];
      const post = (await pool.query('SELECT content FROM posts WHERE id=$1', [l.post_id])).rows[0];
      return { ...l,
        receiverGender: recv?.gender,
        receiverProfile: l.status === 'viewed' ? fmtUser(recv) : null,
        receiverPhone: l.sender_phone_revealed ? recv?.phone : null,
        postContent: post?.content || '' };
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 코인 충전
app.post('/api/coins/purchase', auth, async (req, res) => {
  const { coins } = req.body;
  if (!coins || coins <= 0) return res.status(400).json({ error: '올바르지 않은 수량' });
  try {
    await pool.query('UPDATE users SET coins=coins+$1 WHERE id=$2', [coins, req.user.id]);
    const updated = (await pool.query('SELECT coins FROM users WHERE id=$1', [req.user.id])).rows[0];
    res.json({ coins: updated.coins });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SPA fallback
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// 서버 시작
initDB().then(() => {
  app.listen(PORT, () => console.log(`🌙 익명라운지 실행 중 → http://localhost:${PORT}`));
}).catch(err => {
  console.error('DB 초기화 실패:', err);
  process.exit(1);
});
