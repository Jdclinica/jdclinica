const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jd-clinica-secret-2025';

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Banco de dados
const db = new Database(path.join(__dirname, 'clinica.db'));

// Criar tabelas
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    role TEXT DEFAULT 'psicologa',
    crp TEXT,
    ativo INTEGER DEFAULT 1,
    criado_em TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS pacientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    psicologa_id INTEGER NOT NULL,
    nome TEXT NOT NULL,
    idade TEXT,
    queixa TEXT,
    data_inicio TEXT,
    obs TEXT,
    plano TEXT DEFAULT '{}',
    criado_em TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (psicologa_id) REFERENCES usuarios(id)
  );

  CREATE TABLE IF NOT EXISTS sessoes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER NOT NULL,
    psicologa_id INTEGER NOT NULL,
    num_sessao TEXT,
    data TEXT,
    humor INTEGER,
    extras TEXT DEFAULT '[]',
    topicos TEXT DEFAULT '[]',
    descricao TEXT,
    obs TEXT,
    tarefa TEXT,
    criado_em TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (psicologa_id) REFERENCES usuarios(id)
  );
`);

// Criar admin padrão se não existir
const admin = db.prepare('SELECT id FROM usuarios WHERE email = ?').get('admin@jdclinica.com');
if (!admin) {
  const senha = bcrypt.hashSync('jd2025', 10);
  db.prepare(`INSERT INTO usuarios (nome, email, senha, role, crp) VALUES (?, ?, ?, 'admin', ?)`).run('Administradora', 'admin@jdclinica.com', senha, '');
}

// Middleware de autenticação
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  next();
}

// ===== ROTAS DE AUTH =====
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE email = ? AND ativo = 1').get(email);
  if (!user || !bcrypt.compareSync(senha, user.senha))
    return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
  const token = jwt.sign({ id: user.id, nome: user.nome, email: user.email, role: user.role, crp: user.crp }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, nome: user.nome, email: user.email, role: user.role, crp: user.crp } });
});

app.get('/api/me', auth, (req, res) => res.json(req.user));

app.post('/api/alterar-senha', auth, (req, res) => {
  const { senhaAtual, novaSenha } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(senhaAtual, user.senha))
    return res.status(400).json({ erro: 'Senha atual incorreta' });
  const hash = bcrypt.hashSync(novaSenha, 10);
  db.prepare('UPDATE usuarios SET senha = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

// ===== ROTAS DE USUÁRIOS (admin) =====
app.get('/api/usuarios', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, nome, email, role, crp, ativo, criado_em FROM usuarios').all();
  res.json(users);
});

app.post('/api/usuarios', auth, adminOnly, (req, res) => {
  const { nome, email, senha, role, crp } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Campos obrigatórios: nome, email, senha' });
  try {
    const hash = bcrypt.hashSync(senha, 10);
    const result = db.prepare('INSERT INTO usuarios (nome, email, senha, role, crp) VALUES (?, ?, ?, ?, ?)').run(nome, email, hash, role || 'psicologa', crp || '');
    res.json({ id: result.lastInsertRowid, nome, email, role: role || 'psicologa' });
  } catch (e) {
    res.status(400).json({ erro: 'E-mail já cadastrado' });
  }
});

app.put('/api/usuarios/:id', auth, adminOnly, (req, res) => {
  const { nome, email, crp, ativo, senha } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ erro: 'Usuário não encontrado' });
  const novaSenha = senha ? bcrypt.hashSync(senha, 10) : user.senha;
  db.prepare('UPDATE usuarios SET nome=?, email=?, crp=?, ativo=?, senha=? WHERE id=?').run(nome||user.nome, email||user.email, crp||user.crp, ativo!==undefined?ativo:user.ativo, novaSenha, req.params.id);
  res.json({ ok: true });
});

// ===== ROTAS DE PACIENTES =====
app.get('/api/pacientes', auth, (req, res) => {
  let pacientes;
  if (req.user.role === 'admin') {
    pacientes = db.prepare(`SELECT p.*, u.nome as psicologa_nome FROM pacientes p JOIN usuarios u ON p.psicologa_id = u.id ORDER BY p.criado_em DESC`).all();
  } else {
    pacientes = db.prepare(`SELECT p.*, u.nome as psicologa_nome FROM pacientes p JOIN usuarios u ON p.psicologa_id = u.id WHERE p.psicologa_id = ? ORDER BY p.criado_em DESC`).all(req.user.id);
  }
  pacientes = pacientes.map(p => ({ ...p, plano: JSON.parse(p.plano || '{}') }));
  res.json(pacientes);
});

app.post('/api/pacientes', auth, (req, res) => {
  const { nome, idade, queixa, data_inicio, obs } = req.body;
  if (!nome) return res.status(400).json({ erro: 'Nome obrigatório' });
  const result = db.prepare('INSERT INTO pacientes (psicologa_id, nome, idade, queixa, data_inicio, obs) VALUES (?, ?, ?, ?, ?, ?)').run(req.user.id, nome, idade||'', queixa||'', data_inicio||new Date().toLocaleDateString('pt-BR'), obs||'');
  res.json({ id: result.lastInsertRowid, nome });
});

app.put('/api/pacientes/:id', auth, (req, res) => {
  const pac = db.prepare('SELECT * FROM pacientes WHERE id = ?').get(req.params.id);
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id)
    return res.status(403).json({ erro: 'Sem permissão' });
  const { nome, idade, queixa, data_inicio, obs, plano } = req.body;
  db.prepare('UPDATE pacientes SET nome=?, idade=?, queixa=?, data_inicio=?, obs=?, plano=? WHERE id=?')
    .run(nome||pac.nome, idade||pac.idade, queixa||pac.queixa, data_inicio||pac.data_inicio, obs!==undefined?obs:pac.obs, plano?JSON.stringify(plano):pac.plano, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/pacientes/:id', auth, (req, res) => {
  const pac = db.prepare('SELECT * FROM pacientes WHERE id = ?').get(req.params.id);
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id)
    return res.status(403).json({ erro: 'Sem permissão' });
  db.prepare('DELETE FROM sessoes WHERE paciente_id = ?').run(req.params.id);
  db.prepare('DELETE FROM pacientes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ===== ROTAS DE SESSÕES =====
app.get('/api/sessoes/:pacienteId', auth, (req, res) => {
  const pac = db.prepare('SELECT * FROM pacientes WHERE id = ?').get(req.params.pacienteId);
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id)
    return res.status(403).json({ erro: 'Sem permissão' });
  const sessoes = db.prepare('SELECT * FROM sessoes WHERE paciente_id = ? ORDER BY criado_em ASC').all(req.params.pacienteId);
  res.json(sessoes.map(s => ({ ...s, extras: JSON.parse(s.extras||'[]'), topicos: JSON.parse(s.topicos||'[]') })));
});

app.post('/api/sessoes', auth, (req, res) => {
  const { paciente_id, num_sessao, humor, extras, topicos, descricao, obs, tarefa } = req.body;
  const pac = db.prepare('SELECT * FROM pacientes WHERE id = ?').get(paciente_id);
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id)
    return res.status(403).json({ erro: 'Sem permissão' });
  const result = db.prepare('INSERT INTO sessoes (paciente_id, psicologa_id, num_sessao, data, humor, extras, topicos, descricao, obs, tarefa) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(paciente_id, req.user.id, num_sessao||'', new Date().toLocaleDateString('pt-BR'), humor??null, JSON.stringify(extras||[]), JSON.stringify(topicos||[]), descricao||'', obs||'', tarefa||'');
  res.json({ id: result.lastInsertRowid });
});

// ===== DASHBOARD ADMIN =====
app.get('/api/dashboard', auth, adminOnly, (req, res) => {
  const totalPac = db.prepare('SELECT COUNT(*) as n FROM pacientes').get().n;
  const totalSess = db.prepare('SELECT COUNT(*) as n FROM sessoes').get().n;
  const totalPsi = db.prepare("SELECT COUNT(*) as n FROM usuarios WHERE role = 'psicologa' AND ativo = 1").get().n;
  const porPsicologa = db.prepare(`SELECT u.nome, COUNT(p.id) as pacientes, COUNT(s.id) as sessoes FROM usuarios u LEFT JOIN pacientes p ON p.psicologa_id = u.id LEFT JOIN sessoes s ON s.psicologa_id = u.id WHERE u.ativo = 1 GROUP BY u.id`).all();
  res.json({ totalPac, totalSess, totalPsi, porPsicologa });
});

// Fallback para SPA
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`JD Clínica rodando na porta ${PORT}`));
