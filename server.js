const { MercadoPagoConfig, Preference } = require('mercadopago');
const https = require('https');
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('.'));

const SEGREDO = 'minha-chave-secreta-123';
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

async function chamarIA(prompt, tentativa = 1) {
  const modelo = tentativa === 1 
    ? 'google/gemma-3-4b-it:free' // Modelo principal
    : 'google/gemma-2-9b-it:free'; // Fallback mais estável

  const body = JSON.stringify({
    model: modelo,
    messages: [{ role: 'user', content: prompt }]
  });

  // ... lógica do fetch/request ...
  // Se der erro e tentativa < 2, chama chamarIA(prompt, 2)
}

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

// Middleware: verifica limite de análises
async function verificarLimite(req, res, next) {
  try {
    const userId = req.usuario.id;

    const { rows } = await pool.query(
      'SELECT plano, analises_hoje, ultima_analise FROM usuarios WHERE id = $1',
      [userId]
    );

    const usuarioData = rows[0];

    if (!usuarioData) {
      return res.status(404).json({ sucesso: false, mensagem: 'Usuário não encontrado.' });
    }

    const hoje = new Date().toISOString().split('T')[0];
    let ultimaData = null;
    
    if (usuarioData.ultima_analise) {
        ultimaData = new Date(usuarioData.ultima_analise).toISOString().split('T')[0];
    }

    // 1. Se for PRO, passa direto
    if (usuarioData.plano === 'pro') {
      return next();
    }

    // 2. Reset diário
    let analisesContador = usuarioData.analises_hoje;
    if (ultimaData !== hoje) {
      await pool.query(
        'UPDATE usuarios SET analises_hoje = 0, ultima_analise = $1 WHERE id = $2',
        [hoje, userId]
      );
      analisesContador = 0;
    }

    // 3. Bloqueio do limite Gratuito
    if (analisesContador >= 3) {
      return res.status(403).json({
        erro: 'Limite diário atingido. Faça upgrade para o plano Pro.',
        limite: true
      });
    }

    // 4. Incrementa contador e segue
    await pool.query(
      'UPDATE usuarios SET analises_hoje = analises_hoje + 1, ultima_analise = $1 WHERE id = $2',
      [hoje, userId]
    );

    next();
  } catch (error) {
    console.error('ERRO NO LIMITE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor.' });
  }
}

// --- ROTAS DA FERRAMENTA ---

// Ferramenta protegida
app.get('/ferramenta', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query('SELECT email FROM usuarios WHERE id = $1', [req.usuario.id]);
  res.json({ sucesso: true, mensagem: `Olá ${req.usuario.nome}! Você tem acesso à ferramenta.`, email: rows[0].email });
});

// Rota plano do usuário
app.get('/meu-plano', verificarAcesso, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT plano, analises_hoje, ultima_analise FROM usuarios WHERE id = $1',
    [req.usuario.id]
  );
  
  const usuario = rows[0];
  const hoje = new Date().toISOString().split('T')[0];
  const ultimaData = usuario.ultima_analise 
    ? new Date(usuario.ultima_analise).toISOString().split('T')[0] 
    : null;

  const analisesHoje = ultimaData === hoje ? usuario.analises_hoje : 0;
  const restantes = usuario.plano === 'pro' ? 'ilimitado' : Math.max(0, 3 - analisesHoje);

  res.json({
    plano: usuario.plano,
    analisesHoje,
    restantes
  });
});

// Ativar usuário
app.post('/ativar', async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE usuarios SET ativo = 1 WHERE email = $1', [email]);
  res.json({ sucesso: true, mensagem: `${email} ativado!` });
});

// Admin
app.get('/admin/usuarios', async (req, res) => {
  const result = await pool.query('SELECT id, nome, email, ativo, plano FROM usuarios');
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
// Rota de análise com Fallback (Plano B) e melhor tratamento de erros
app.post('/analisar', verificarAcesso, verificarLimite, async (req, res) => {
  const { prompt } = req.body;

  // Função interna para fazer a chamada à API
  async function fazerChamada(modelo) {
    return new Promise((resolve, reject) => {
      const body = JSON.stringify({
        model: modelo,
        messages: [{ role: 'user', content: prompt }]
      });

      const options = {
        hostname: 'openrouter.ai',
        path: '/api/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: 20000 // 20 segundos para desistir
      };

      const request = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          try {
            const json = JSON.parse(data);
            if (json.choices && json.choices[0]) {
              resolve(json);
            } else {
              reject('Resposta inválida do OpenRouter');
            }
          } catch (e) {
            reject('Erro ao processar JSON');
          }
        });
      });

      request.on('error', (e) => reject(e.message));
      request.on('timeout', () => {
        request.destroy();
        reject('Tempo esgotado');
      });
      request.write(body);
      request.end();
    });
  }

  try {
    // TENTATIVA 1: Modelo Principal (Gemma)
    console.log('Tentando modelo principal...');
    const resultado = await fazerChamada('google/gemma-2-9b-it:free');
    res.json(resultado);

  } catch (erro) {
    console.log('Modelo principal falhou, tentando Fallback (Llama)...', erro);
    
    try {
      // TENTATIVA 2: Modelo Reserva (Llama - costuma ser muito estável)
      const fallback = await fazerChamada('meta-llama/llama-3-8b-instruct:free');
      res.json(fallback);
    } catch (erro2) {
      console.error('Ambos os modelos falharam.');
      res.status(500).json({ error: 'Sistema de IA instável. Tente novamente em 30 segundos.' });
    }
  }
});

// Criar pagamento
app.post('/criar-pagamento', async (req, res) => {
  res.json({ sucesso: true, url: 'https://mpago.la/2D6c6S4' });
});

// Rotas de debug — remover após confirmar funcionamento
app.get('/debug-db', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT table_name FROM information_schema.tables 
    WHERE table_schema = 'public'
  `);
  res.json(rows);
});

app.get('/debug-colunas', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT column_name, data_type, column_default 
    FROM information_schema.columns 
    WHERE table_name = 'usuarios'
  `);
  res.json(rows);
});
app.get('/callback', (req, res) => {
  const code = req.query.code;
  res.send(`<h2>Seu code:</h2><p style="font-size:20px; word-break:break-all;">${code}</p>`);
});
app.get('/teste-ml', async (req, res) => {
  const https = require('https');
  const options = {
    hostname: 'api.mercadolibre.com',
    path: '/users/me',
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${process.env.ML_ACCESS_TOKEN}`
    }
  };
  const request = https.request(options, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.json(JSON.parse(data)));
  });
  request.on('error', (e) => res.json({ error: e.message }));
  request.end();
});
app.post('/admin/plano', async (req, res) => {
  const { email, plano } = req.body;
  await pool.query('UPDATE usuarios SET plano = $1 WHERE email = $2', [plano, email]);
  res.json({ sucesso: true, mensagem: `${email} agora é ${plano}!` });
});
app.get('/debug-mp', (req, res) => {
  res.json({ token: process.env.MP_ACCESS_TOKEN ? process.env.MP_ACCESS_TOKEN.substring(0, 20) + '...' : 'NAO DEFINIDO' });
});

app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor rodando na porta ${PORT}`);
});
