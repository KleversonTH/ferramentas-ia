const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('.'));

const db = new Database('banco.db');
const SEGREDO = 'minha-chave-secreta-123';

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    ativo INTEGER DEFAULT 0
  )
`);

// Rota de cadastro
app.post('/cadastro', (req, res) => {
  const { nome, email, senha } = req.body;
  try {
    db.prepare('INSERT INTO usuarios (nome, email, senha, ativo) VALUES (?, ?, ?, 0)').run(nome, email, senha);
    res.json({ sucesso: true, mensagem: 'Cadastro realizado! Aguarde a ativação.' });
  } catch (e) {
    res.json({ sucesso: false, mensagem: 'Email já cadastrado.' });
  }
});

// Rota de login
app.post('/login', (req, res) => {
  const { email, senha } = req.body;
  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ? AND senha = ?').get(email, senha);

  if (usuario) {
    const token = jwt.sign({ id: usuario.id, nome: usuario.nome, ativo: usuario.ativo }, SEGREDO, { expiresIn: '7d' });
    res.json({ sucesso: true, token, ativo: usuario.ativo === 1, mensagem: `Bem vindo, ${usuario.nome}!` });
  } else {
    res.json({ sucesso: false, mensagem: 'Email ou senha incorretos.' });
  }
});

// Middleware que verifica token e se está ativo
function verificarAcesso(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.json({ sucesso: false, mensagem: 'Acesso negado. Faça login.' });

  try {
    const dados = jwt.verify(token, SEGREDO);
    if (dados.ativo !== 1) return res.json({ sucesso: false, mensagem: 'Conta não ativada. Realize o pagamento.' });
    req.usuario = dados;
    next();
  } catch (e) {
    res.json({ sucesso: false, mensagem: 'Token inválido ou expirado.' });
  }
}

// Rota protegida — só acessa quem pagou
app.get('/ferramenta', verificarAcesso, (req, res) => {
  res.json({ sucesso: true, mensagem: `Olá ${req.usuario.nome}! Você tem acesso à ferramenta.` });
});

// Rota para ativar usuário (você chama manualmente após pagamento)
app.post('/ativar', (req, res) => {
  const { email } = req.body;
  db.prepare('UPDATE usuarios SET ativo = 1 WHERE email = ?').run(email);
  res.json({ sucesso: true, mensagem: `Usuário ${email} ativado com sucesso!` });
});

// Listar usuários
app.get('/usuarios', (req, res) => {
  const usuarios = db.prepare('SELECT id, nome, email, ativo FROM usuarios').all();
  res.json(usuarios);
});

// Rota admin — lista todos usuários
app.get('/admin/usuarios', (req, res) => {
  const usuarios = db.prepare('SELECT id, nome, email, ativo FROM usuarios').all();
  res.json(usuarios);
});

// Rota admin — ativar usuário
app.post('/admin/ativar', (req, res) => {
  const { email } = req.body;
  db.prepare('UPDATE usuarios SET ativo = 1 WHERE email = ?').run(email);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

// Rota admin — desativar usuário
app.post('/admin/desativar', (req, res) => {
  const { email } = req.body;
  db.prepare('UPDATE usuarios SET ativo = 0 WHERE email = ?').run(email);
  res.json({ sucesso: true, mensagem: `${email} desativado!` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});