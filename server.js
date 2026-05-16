const { MercadoPagoConfig, Preference } = require('mercadopago');
const https = require('https');
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// ✅ HELMET — headers de segurança HTTP
app.use(helmet({
  contentSecurityPolicy: false, // desativado para não quebrar os scripts inline do frontend
  crossOriginEmbedderPolicy: false
}));

// ✅ CORS — só aceita requisições dos domínios autorizados
const dominiosPermitidos = [
  'https://ferramentas-ia-production.up.railway.app',
  'https://www.revendaia.com.br',
  'https://revendaia.com.br',
  'http://localhost:3000',
  'http://localhost:8080'
];

app.use(cors({
  origin: function(origin, callback) {
    // Permite requisições sem origin (ex: Railway, Postman, webhooks do MP)
    if (!origin) return callback(null, true);
    if (dominiosPermitidos.includes(origin)) return callback(null, true);
    callback(new Error('Origem não permitida pelo CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'authorization']
}));

app.use(express.json({ limit: '10kb' })); // ✅ Limita tamanho do body para evitar ataques
app.use(express.static('.'));

const SEGREDO = process.env.JWT_SECRET || 'minha-chave-secreta-123';
const BASE_URL = process.env.APP_URL || 'https://ferramentas-ia-production.up.railway.app';
const mp = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ✅ RATE LIMITING — controle de tentativas por IP (em memória)
const tentativasLogin = new Map();
const tentativasCadastro = new Map();

function limparTentativasAntigas(mapa, janela) {
  const agora = Date.now();
  for (const [ip, dados] of mapa.entries()) {
    if (agora - dados.inicio > janela) mapa.delete(ip);
  }
}

function verificarRateLimit(mapa, ip, maxTentativas, janela, res, mensagem) {
  limparTentativasAntigas(mapa, janela);
  const agora = Date.now();
  const dados = mapa.get(ip) || { tentativas: 0, inicio: agora };
  if (agora - dados.inicio > janela) { dados.tentativas = 0; dados.inicio = agora; }
  dados.tentativas++;
  mapa.set(ip, dados);
  if (dados.tentativas > maxTentativas) {
    const restante = Math.ceil((janela - (agora - dados.inicio)) / 1000);
    res.status(429).json({ sucesso: false, mensagem: `${mensagem} Tente novamente em ${restante} segundos.` });
    return false;
  }
  return true;
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      ativo INTEGER DEFAULT 0,
      plano VARCHAR(20) DEFAULT 'gratuito',
      analises_hoje INTEGER DEFAULT 0,
      ultima_analise DATE
    )
  `);
}

// --- MIDDLEWARES ---

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

function verificarAdmin(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ sucesso: false, mensagem: 'Acesso negado.' });
  try {
    const dados = jwt.verify(token, SEGREDO);
    if (!dados.admin) return res.status(401).json({ sucesso: false, mensagem: 'Acesso negado.' });
    next();
  } catch (e) {
    res.status(401).json({ sucesso: false, mensagem: 'Token inválido ou expirado.' });
  }
}

async function verificarLimite(req, res, next) {
  try {
    const userId = req.usuario.id;
    const { rows } = await pool.query('SELECT plano, analises_hoje, ultima_analise FROM usuarios WHERE id = $1', [userId]);
    const usuarioData = rows[0];
    if (!usuarioData) return res.status(404).json({ sucesso: false, mensagem: 'Usuário não encontrado.' });

    const hoje = new Date().toISOString().split('T')[0];
    let ultimaData = usuarioData.ultima_analise ? new Date(usuarioData.ultima_analise).toISOString().split('T')[0] : null;

    if (usuarioData.plano === 'pro') return next();

    if (ultimaData !== hoje) {
      await pool.query('UPDATE usuarios SET analises_hoje = 0, ultima_analise = $1 WHERE id = $2', [hoje, userId]);
      usuarioData.analises_hoje = 0;
    }

    if (usuarioData.analises_hoje >= 1) {
      return res.status(403).json({ erro: 'Limite diário atingido. Faça upgrade para o plano Pro.', limite: true });
    }

    await pool.query('UPDATE usuarios SET analises_hoje = analises_hoje + 1, ultima_analise = $1 WHERE id = $2', [hoje, userId]);
    next();
  } catch (error) {
    console.error('ERRO NO LIMITE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor.' });
  }
}

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/cadastro', async (req, res) => {
  const ip = getIP(req);
  if (!verificarRateLimit(tentativasCadastro, ip, 5, 60 * 60 * 1000, res, 'Muitos cadastros deste IP.')) return;

  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) return res.json({ sucesso: false, mensagem: 'Preencha todos os campos.' });
  if (senha.length < 6) return res.json({ sucesso: false, mensagem: 'A senha deve ter pelo menos 6 caracteres.' });
  if (!email.includes('@')) return res.json({ sucesso: false, mensagem: 'Email inválido.' });
  if (nome.length > 100 || email.length > 200) return res.json({ sucesso: false, mensagem: 'Dados inválidos.' });

  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    await pool.query('INSERT INTO usuarios (nome, email, senha, ativo) VALUES ($1, $2, $3, 0)', [nome, email, senhaHash]);
    res.json({ sucesso: true, mensagem: 'Cadastro realizado! Aguarde a ativação.' });
  } catch (e) {
    res.json({ sucesso: false, mensagem: 'Email já cadastrado.' });
  }
});

app.post('/login', async (req, res) => {
  const ip = getIP(req);
  if (!verificarRateLimit(tentativasLogin, ip, 10, 15 * 60 * 1000, res, 'Muitas tentativas de login.')) return;

  const { email, senha } = req.body;
  if (!email || !senha) return res.json({ sucesso: false, mensagem: 'Preencha todos os campos.' });

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const usuario = result.rows[0];
    if (!usuario) return res.json({ sucesso: false, mensagem: 'Email ou senha incorretos.' });

    let senhaCorreta = false;
    if (usuario.senha.startsWith('$2b$') || usuario.senha.startsWith('$2a$')) {
      senhaCorreta = await bcrypt.compare(senha, usuario.senha);
    } else {
      senhaCorreta = (senha === usuario.senha);
      if (senhaCorreta) {
        const senhaHash = await bcrypt.hash(senha, 10);
        await pool.query('UPDATE usuarios SET senha = $1 WHERE id = $2', [senhaHash, usuario.id]);
        console.log(`Senha migrada para bcrypt: ${usuario.email}`);
      }
    }

    if (!senhaCorreta) return res.json({ sucesso: false, mensagem: 'Email ou senha incorretos.' });

    tentativasLogin.delete(ip);
    const token = jwt.sign({ id: usuario.id, nome: usuario.nome, ativo: usuario.ativo }, SEGREDO, { expiresIn: '7d' });
    res.json({ sucesso: true, token, ativo: usuario.ativo === 1, nome: usuario.nome, mensagem: `Bem vindo, ${usuario.nome}!` });
  } catch (e) {
    console.error('ERRO LOGIN:', e);
    res.json({ sucesso: false, mensagem: 'Erro ao fazer login. Tente novamente.' });
  }
});

app.get('/me', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query('SELECT nome, email, plano FROM usuarios WHERE id = $1', [req.usuario.id]);
  const usuario = rows[0];
  res.json({ sucesso: true, nome: usuario.nome, email: usuario.email, plano: usuario.plano });
});

// --- CHAMADA IA COM RETRY ---

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function fazerChamadaIA(prompt, tentativa = 1) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: 'meta-llama/llama-3.3-70b-instruct',
      messages: [{ role: 'user', content: prompt }],
      stream: false
    });

    const options = {
      hostname: 'openrouter.ai',
      path: '/api/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'HTTP-Referer': BASE_URL,
        'X-Title': 'Revenda IA'
      }
    };

    const req = https.request(options, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', async () => {
        console.log(`STATUS: ${response.statusCode} | TAMANHO: ${data.length} bytes`);
        try {
          const json = JSON.parse(data);
          if (json.error) {
            const msgErro = json.error.message || 'Erro desconhecido';
            console.error(`ERRO OPENROUTER (tentativa ${tentativa}):`, msgErro);
            if (json.error.code === 402 || msgErro.toLowerCase().includes('credit') || msgErro.toLowerCase().includes('balance')) {
              return reject({ tipo: 'sem_saldo' });
            }
            if (tentativa < 3) { await sleep(tentativa * 2000); return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject); }
            return reject({ tipo: 'erro_api' });
          }
          if (json.choices && json.choices[0] && json.choices[0].message && json.choices[0].message.content) {
            return resolve(json.choices[0].message.content);
          }
          if (tentativa < 3) { await sleep(tentativa * 2000); return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject); }
          reject({ tipo: 'erro_resposta' });
        } catch (e) {
          if (tentativa < 3) { await sleep(tentativa * 2000); return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject); }
          reject({ tipo: 'erro_parse' });
        }
      });
    });

    req.on('error', async (e) => {
      if (tentativa < 3) { await sleep(tentativa * 2000); return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject); }
      reject({ tipo: 'erro_rede' });
    });

    req.setTimeout(60000, () => {
      req.destroy();
      if (tentativa < 3) { sleep(tentativa * 2000).then(() => fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject)); }
      else reject({ tipo: 'timeout' });
    });

    req.write(body);
    req.end();
  });
}

app.post('/analisar', verificarAcesso, verificarLimite, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt || prompt.length > 5000) return res.status(400).json({ sucesso: false, mensagem: 'Prompt inválido.' });
  console.log("=== ANÁLISE RECEBIDA ===");
  try {
    const analise = await fazerChamadaIA(prompt);
    res.json({ sucesso: true, analise });
  } catch (error) {
    console.error("FALHA NA ANÁLISE:", error);
    const mensagens = {
      sem_saldo: 'Serviço temporariamente indisponível. Contate o suporte.',
      timeout: 'A IA demorou para responder. Tente novamente.',
      erro_rede: 'Erro de conexão. Tente novamente.',
      erro_api: 'Erro no serviço de IA. Tente novamente mais tarde.',
      erro_resposta: 'Resposta inválida da IA. Tente novamente.',
      erro_parse: 'Erro ao processar resposta. Tente novamente.'
    };
    const msg = (error.tipo && mensagens[error.tipo]) ? mensagens[error.tipo] : 'Erro inesperado. Tente novamente.';
    res.status(500).json({ sucesso: false, mensagem: msg });
  }
});

// --- ROTAS DE PLANO ---

app.get('/meu-plano', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query('SELECT plano, analises_hoje, ultima_analise FROM usuarios WHERE id = $1', [req.usuario.id]);
  const usuario = rows[0];
  const hoje = new Date().toISOString().split('T')[0];
  const analisesHoje = (usuario.ultima_analise && new Date(usuario.ultima_analise).toISOString().split('T')[0] === hoje) ? usuario.analises_hoje : 0;
  res.json({ plano: usuario.plano, analisesHoje, restantes: usuario.plano === 'pro' ? 'ilimitado' : Math.max(0, 3 - analisesHoje) });
});

app.post('/criar-pagamento', verificarAcesso, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT nome, email FROM usuarios WHERE id = $1', [req.usuario.id]);
    const usuario = rows[0];
    const preference = new Preference(mp);
    const resultado = await preference.create({
      body: {
        items: [{ title: 'Revenda IA — Plano Pro', quantity: 1, currency_id: 'BRL', unit_price: 19.90 }],
        payer: { name: usuario.nome, email: usuario.email },
        back_urls: { success: `${BASE_URL}/pagamento-sucesso.html`, failure: `${BASE_URL}/login.html`, pending: `${BASE_URL}/pagamento-pendente.html` },
        auto_return: 'approved',
        notification_url: `${BASE_URL}/webhook-mp`,
        external_reference: String(req.usuario.id)
      }
    });
    res.json({ sucesso: true, url: resultado.init_point });
  } catch (e) {
    console.error('ERRO CRIAR PAGAMENTO:', e);
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao criar pagamento.' });
  }
});

app.post('/webhook-mp', async (req, res) => {
  try {
    const { type, data } = req.body;
    console.log('WEBHOOK MP:', type, data);
    if (type === 'payment' && data && data.id) {
      const pagamento = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, {
        headers: { 'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}` }
      }).then(r => r.json());
      console.log('PAGAMENTO STATUS:', pagamento.status, '| USER:', pagamento.external_reference);
      if (pagamento.status === 'approved' && pagamento.external_reference) {
        const userId = parseInt(pagamento.external_reference);
        await pool.query('UPDATE usuarios SET plano = $1, ativo = 1 WHERE id = $2', ['pro', userId]);
        console.log(`✅ Usuário ${userId} ativado como Pro!`);
      }
    }
    res.sendStatus(200);
  } catch (e) {
    console.error('ERRO WEBHOOK:', e);
    res.sendStatus(200);
  }
});

// --- ROTAS ADMIN (protegidas) ---

app.post('/admin/login', async (req, res) => {
  const ip = getIP(req);
  if (!verificarRateLimit(tentativasLogin, ip + '_admin', 5, 30 * 60 * 1000, res, 'Muitas tentativas no admin.')) return;

  const { email, senha } = req.body;
  if (email === process.env.ADMIN_EMAIL && senha === process.env.ADMIN_SENHA) {
    tentativasLogin.delete(ip + '_admin');
    const token = jwt.sign({ admin: true }, SEGREDO, { expiresIn: '8h' });
    res.json({ sucesso: true, token });
  } else {
    res.json({ sucesso: false, mensagem: 'Credenciais inválidas.' });
  }
});

app.get('/admin/usuarios', verificarAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, nome, email, ativo, plano FROM usuarios ORDER BY id DESC');
  res.json(rows);
});

app.post('/admin/ativar', verificarAdmin, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 1 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

app.post('/admin/desativar', verificarAdmin, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 0 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} desativado!` });
});

app.post('/admin/plano', verificarAdmin, async (req, res) => {
  const { email, plano } = req.body;
  await pool.query('UPDATE usuarios SET plano = $1 WHERE email = $2', [plano, email]);
  res.json({ sucesso: true, mensagem: `${email} agora é ${plano}!` });
});

app.post('/admin/excluir', verificarAdmin, async (req, res) => {
  const { email } = req.body;
  await pool.query('DELETE FROM usuarios WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} excluído!` });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor rodando na porta ${PORT}`);
});
