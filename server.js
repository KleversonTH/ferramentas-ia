const fetch = require('node-fetch');
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('.'));

const SEGREDO = 'minha-chave-secreta-123';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      ativo INTEGER DEFAULT 0
    )
  `);
}

// Cadastro
app.post('/cadastro', async (req, res) => {
  const { nome, email, senha } = req.body;
  try {
    await pool.query('INSERT INTO usuarios (nome, email, senha, ativo) VALUES ($1, $2, $3, 0)', [nome, email, senha]);
    res.json({ sucesso: true, mensagem: 'Cadastro realizado! Aguarde a ativação.' });
  } catch (e) {
    res.json({ sucesso: false, mensagem: 'Email já cadastrado.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE email = $1 AND senha = $2', [email, senha]);
  const usuario = result.rows[0];
  if (usuario) {
    const token = jwt.sign({ id: usuario.id, nome: usuario.nome, ativo: usuario.ativo }, SEGREDO, { expiresIn: '7d' });
    res.json({ sucesso: true, token, ativo: usuario.ativo === 1, mensagem: `Bem vindo, ${usuario.nome}!` });
  } else {
    res.json({ sucesso: false, mensagem: 'Email ou senha incorretos.' });
  }
});

// Middleware token
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

// Ferramenta protegida
app.get('/ferramenta', verificarAcesso, (req, res) => {
  res.json({ sucesso: true, mensagem: `Olá ${req.usuario.nome}! Você tem acesso à ferramenta.` });
});

// Ativar usuário
app.post('/ativar', async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 1 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

// Admin
app.get('/admin/usuarios', async (req, res) => {
  const result = await pool.query('SELECT id, nome, email, ativo FROM usuarios');
  res.json(result.rows);
});

app.post('/admin/ativar', async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 1 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

app.post('/admin/desativar', async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 0 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} desativado!` });
});

const PORT = process.env.PORT || 3000;
app.post('/admin/excluir', async (req, res) => {
  const { email } = req.body;
  await pool.query('DELETE FROM usuarios WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} excluído!` });
});

// Rota que chama o OpenRouter com a chave protegida
app.post('/analisar', verificarAcesso, async (req, res) => {
  const { prompt } = req.body;
  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`
      },
      body: JSON.stringify({
        model: 'google/gemma-3-4b-it:free',
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await response.json();
    console.log('Resposta OpenRouter:', JSON.stringify(data));
    res.json(data);
  } catch (e) {
    console.log('Erro:', e.message);
    res.json({ error: 'Erro ao chamar API' });
  }
});