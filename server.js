const { MercadoPagoConfig } = require('mercadopago');
const https = require('https');
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('.'));

const SEGREDO = process.env.JWT_SECRET || 'minha-chave-secreta-123';
const mp = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

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

    if (usuarioData.analises_hoje >= 3) {
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
  const { nome, email, senha } = req.body;
  try {
    await pool.query('INSERT INTO usuarios (nome, email, senha, ativo) VALUES ($1, $2, $3, 0)', [nome, email, senha]);
    res.json({ sucesso: true, mensagem: 'Cadastro realizado! Aguarde a ativação.' });
  } catch (e) {
    res.json({ sucesso: false, mensagem: 'Email já cadastrado.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE email = $1 AND senha = $2', [email, senha]);
  const usuario = result.rows[0];
  if (usuario) {
    const token = jwt.sign({ id: usuario.id, nome: usuario.nome, ativo: usuario.ativo }, SEGREDO, { expiresIn: '7d' });
    res.json({ sucesso: true, token, ativo: usuario.ativo === 1, nome: usuario.nome, mensagem: `Bem vindo, ${usuario.nome}!` });
  } else {
    res.json({ sucesso: false, mensagem: 'Email ou senha incorretos.' });
  }
});

// ✅ Rota para verificar token e retornar dados do usuário
app.get('/me', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query('SELECT nome, email, plano FROM usuarios WHERE id = $1', [req.usuario.id]);
  const usuario = rows[0];
  res.json({ sucesso: true, nome: usuario.nome, email: usuario.email, plano: usuario.plano });
});

// --- CHAMADA IA COM RETRY ---

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function fazerChamadaIA(prompt, tentativa = 1) {
  const APP_URL = process.env.APP_URL || 'https://ferramentas-ia-production.up.railway.app';

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
        'HTTP-Referer': APP_URL,
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
            if (tentativa < 3) {
              await sleep(tentativa * 2000);
              return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject);
            }
            return reject({ tipo: 'erro_api' });
          }

          if (json.choices && json.choices[0] && json.choices[0].message && json.choices[0].message.content) {
            return resolve(json.choices[0].message.content);
          }

          console.error('RESPOSTA INESPERADA:', JSON.stringify(json).substring(0, 300));
          if (tentativa < 3) {
            await sleep(tentativa * 2000);
            return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject);
          }
          reject({ tipo: 'erro_resposta' });

        } catch (e) {
          console.error('ERRO PARSE:', e.message, '| DATA:', data.substring(0, 200));
          if (tentativa < 3) {
            await sleep(tentativa * 2000);
            return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject);
          }
          reject({ tipo: 'erro_parse' });
        }
      });
    });

    req.on('error', async (e) => {
      console.error(`Erro de rede (tentativa ${tentativa}):`, e.message);
      if (tentativa < 3) {
        await sleep(tentativa * 2000);
        return fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject);
      }
      reject({ tipo: 'erro_rede' });
    });

    req.setTimeout(60000, () => {
      req.destroy();
      console.warn(`Timeout na tentativa ${tentativa}`);
      if (tentativa < 3) {
        sleep(tentativa * 2000).then(() => fazerChamadaIA(prompt, tentativa + 1).then(resolve).catch(reject));
      } else {
        reject({ tipo: 'timeout' });
      }
    });

    req.write(body);
    req.end();
  });
}

app.post('/analisar', verificarAcesso, verificarLimite, async (req, res) => {
  const { prompt } = req.body;
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

// --- ROTAS DE PLANO E ADMIN ---

app.get('/meu-plano', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query('SELECT plano, analises_hoje, ultima_analise FROM usuarios WHERE id = $1', [req.usuario.id]);
  const usuario = rows[0];
  const hoje = new Date().toISOString().split('T')[0];
  const analisesHoje = (usuario.ultima_analise && new Date(usuario.ultima_analise).toISOString().split('T')[0] === hoje) ? usuario.analises_hoje : 0;
  res.json({ plano: usuario.plano, analisesHoje, restantes: usuario.plano === 'pro' ? 'ilimitado' : Math.max(0, 3 - analisesHoje) });
});

app.post('/criar-pagamento', async (req, res) => {
  res.json({ sucesso: true, url: 'https://mpago.la/2D6c6S4' });
});

app.post('/admin/plano', async (req, res) => {
  const { email, plano } = req.body;
  await pool.query('UPDATE usuarios SET plano = $1 WHERE email = $2', [plano, email]);
  res.json({ sucesso: true, mensagem: `${email} agora é ${plano}!` });
});

app.post('/admin/ativar', async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 1 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor rodando na porta ${PORT}`);
});
