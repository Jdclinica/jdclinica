const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jd-clinica-secret-2025';

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Banco de dados em memória (compatível com Render free)
let db = {
  usuarios: [],
  pacientes: [],
  sessoes: [],
  nextId: { usuarios: 1, pacientes: 1, sessoes: 1 }
};

// Criar admin padrão
const senhaAdmin = bcrypt.hashSync('jd2025', 10);
db.usuarios.push({ id: 1, nome: 'Administradora', email: 'admin@jdclinica.com', senha: senhaAdmin, role: 'admin', crp: '', ativo: 1, criado_em: new Date().toISOString() });
db.nextId.usuarios = 2;

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

// ===== AUTH =====
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;
  const user = db.usuarios.find(u => u.email === email && u.ativo === 1);
  if (!user || !bcrypt.compareSync(senha, user.senha))
    return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
  const token = jwt.sign({ id: user.id, nome: user.nome, email: user.email, role: user.role, crp: user.crp }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, nome: user.nome, email: user.email, role: user.role, crp: user.crp } });
});

app.get('/api/me', auth, (req, res) => res.json(req.user));

app.post('/api/alterar-senha', auth, (req, res) => {
  const { senhaAtual, novaSenha } = req.body;
  const user = db.usuarios.find(u => u.id === req.user.id);
  if (!bcrypt.compareSync(senhaAtual, user.senha))
    return res.status(400).json({ erro: 'Senha atual incorreta' });
  user.senha = bcrypt.hashSync(novaSenha, 10);
  res.json({ ok: true });
});

// ===== USUÁRIOS =====
app.get('/api/usuarios', auth, adminOnly, (req, res) => {
  res.json(db.usuarios.map(u => ({ id: u.id, nome: u.nome, email: u.email, role: u.role, crp: u.crp, ativo: u.ativo, criado_em: u.criado_em })));
});

app.post('/api/usuarios', auth, adminOnly, (req, res) => {
  const { nome, email, senha, role, crp } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Campos obrigatórios: nome, email, senha' });
  if (db.usuarios.find(u => u.email === email)) return res.status(400).json({ erro: 'E-mail já cadastrado' });
  const hash = bcrypt.hashSync(senha, 10);
  const novo = { id: db.nextId.usuarios++, nome, email, senha: hash, role: role || 'psicologa', crp: crp || '', ativo: 1, criado_em: new Date().toISOString() };
  db.usuarios.push(novo);
  res.json({ id: novo.id, nome, email, role: novo.role });
});

app.put('/api/usuarios/:id', auth, adminOnly, (req, res) => {
  const user = db.usuarios.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ erro: 'Usuário não encontrado' });
  const { nome, email, crp, ativo, senha } = req.body;
  if (nome) user.nome = nome;
  if (email) user.email = email;
  if (crp !== undefined) user.crp = crp;
  if (ativo !== undefined) user.ativo = ativo;
  if (senha) user.senha = bcrypt.hashSync(senha, 10);
  res.json({ ok: true });
});

// ===== PACIENTES =====
app.get('/api/pacientes', auth, (req, res) => {
  let lista = req.user.role === 'admin' ? db.pacientes : db.pacientes.filter(p => p.psicologa_id === req.user.id);
  lista = lista.map(p => {
    const psi = db.usuarios.find(u => u.id === p.psicologa_id);
    const sessoesPac = db.sessoes.filter(s => s.paciente_id === p.id);
    const ultima = sessoesPac[sessoesPac.length - 1];
    return { ...p, psicologa_nome: psi ? psi.nome : '', total_sessoes: sessoesPac.length, ultimo_humor: ultima ? ultima.humor : null };
  });
  res.json(lista);
});

app.post('/api/pacientes', auth, (req, res) => {
  const { nome, idade, queixa, data_inicio, obs } = req.body;
  if (!nome) return res.status(400).json({ erro: 'Nome obrigatório' });
  const novo = { id: db.nextId.pacientes++, psicologa_id: req.user.id, nome, idade: idade||'', queixa: queixa||'', data_inicio: data_inicio||new Date().toLocaleDateString('pt-BR'), obs: obs||'', plano: {}, criado_em: new Date().toISOString() };
  db.pacientes.push(novo);
  res.json({ id: novo.id, nome });
});

app.put('/api/pacientes/:id', auth, (req, res) => {
  const pac = db.pacientes.find(p => p.id === parseInt(req.params.id));
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id) return res.status(403).json({ erro: 'Sem permissão' });
  const { nome, idade, queixa, data_inicio, obs, plano } = req.body;
  if (nome) pac.nome = nome;
  if (idade !== undefined) pac.idade = idade;
  if (queixa !== undefined) pac.queixa = queixa;
  if (data_inicio) pac.data_inicio = data_inicio;
  if (obs !== undefined) pac.obs = obs;
  if (plano !== undefined) pac.plano = plano;
  res.json({ ok: true });
});

app.delete('/api/pacientes/:id', auth, (req, res) => {
  const idx = db.pacientes.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && db.pacientes[idx].psicologa_id !== req.user.id) return res.status(403).json({ erro: 'Sem permissão' });
  db.sessoes = db.sessoes.filter(s => s.paciente_id !== parseInt(req.params.id));
  db.pacientes.splice(idx, 1);
  res.json({ ok: true });
});

// ===== SESSÕES =====
app.get('/api/sessoes/:pacienteId', auth, (req, res) => {
  const pac = db.pacientes.find(p => p.id === parseInt(req.params.pacienteId));
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id) return res.status(403).json({ erro: 'Sem permissão' });
  res.json(db.sessoes.filter(s => s.paciente_id === parseInt(req.params.pacienteId)));
});

app.post('/api/sessoes', auth, (req, res) => {
  const { paciente_id, num_sessao, humor, extras, topicos, descricao, obs, tarefa } = req.body;
  const pac = db.pacientes.find(p => p.id === parseInt(paciente_id));
  if (!pac) return res.status(404).json({ erro: 'Paciente não encontrada' });
  if (req.user.role !== 'admin' && pac.psicologa_id !== req.user.id) return res.status(403).json({ erro: 'Sem permissão' });
  const nova = { id: db.nextId.sessoes++, paciente_id: parseInt(paciente_id), psicologa_id: req.user.id, num_sessao: num_sessao||'', data: new Date().toLocaleDateString('pt-BR'), humor: humor??null, extras: extras||[], topicos: topicos||[], descricao: descricao||'', obs: obs||'', tarefa: tarefa||'', criado_em: new Date().toISOString() };
  db.sessoes.push(nova);
  res.json({ id: nova.id });
});

// ===== DASHBOARD =====
app.get('/api/dashboard', auth, adminOnly, (req, res) => {
  const totalPac = db.pacientes.length;
  const totalSess = db.sessoes.length;
  const totalPsi = db.usuarios.filter(u => u.role === 'psicologa' && u.ativo === 1).length;
  const porPsicologa = db.usuarios.filter(u => u.ativo === 1).map(u => ({
    nome: u.nome,
    pacientes: db.pacientes.filter(p => p.psicologa_id === u.id).length,
    sessoes: db.sessoes.filter(s => s.psicologa_id === u.id).length
  }));
  res.json({ totalPac, totalSess, totalPsi, porPsicologa });
});

app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`JD Clínica rodando na porta ${PORT}`));
