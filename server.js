// npm install && node server.js
// Acesse: http://localhost:3000

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs/promises');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'neon_kanban_super_secret_key_2026';


const USERS_FILE = path.join(__dirname, 'users.json');
const TASKS_FILE = path.join(__dirname, 'tasks.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helpers para leitura e escrita de arquivos
async function readJson(file) {
  try {
    const data = await fs.readFile(file, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

async function writeJson(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2), 'utf8');
}


// Middleware de autenticação
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
        return res.status(401).json({ message: 'Token expirado ou inválido.' });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
  }
};

// ========================
// Rotas de Autenticação
// ========================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Nome, e-mail e senha são obrigatórios.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'A senha deve ter pelo menos 6 caracteres.' });
    }

    const users = await readJson(USERS_FILE);
    
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ message: 'E-mail já está em uso.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeJson(USERS_FILE, users);

    res.status(201).json({ message: 'Usuário registrado com sucesso.' });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
    }

    const users = await readJson(USERS_FILE);
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    // Token expira em 8 horas
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, SECRET_KEY, { expiresIn: '8h' });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// ========================
// Rotas de Tarefas (Protegidas)
// ========================

// Listar tarefas do usuário
app.get('/api/tasks', authenticateJWT, async (req, res) => {
  try {
    const tasks = await readJson(TASKS_FILE);
    const userTasks = tasks.filter(t => t.userId === req.user.id);
    res.json(userTasks);
  } catch (error) {
    console.error('Erro ao buscar tarefas:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Criar tarefa
app.post('/api/tasks', authenticateJWT, async (req, res) => {
  try {
    const { title, description, responsible, status, deadline } = req.body;

    if (!title || !status) {
      return res.status(400).json({ message: 'Título e status são obrigatórios.' });
    }

    const tasks = await readJson(TASKS_FILE);
    
    // Gerar iniciais para o avatar
    let responsibleAvatar = '??';
    if (responsible) {
      const parts = responsible.trim().split(' ');
      if (parts.length > 1) {
        responsibleAvatar = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      } else {
        responsibleAvatar = responsible.substring(0, 2).toUpperCase();
      }
    }

    const newTask = {
      id: uuidv4(),
      userId: req.user.id,
      title,
      description: description || '',
      responsible: responsible || req.user.name,
      responsibleAvatar,
      status, // "todo" | "doing" | "done"
      completed: false,
      deadline: deadline || null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    tasks.push(newTask);
    await writeJson(TASKS_FILE, tasks);

    res.status(201).json(newTask);
  } catch (error) {
    console.error('Erro ao criar tarefa:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Editar tarefa
app.put('/api/tasks/:id', authenticateJWT, async (req, res) => {
  try {
    const { title, description, responsible, deadline, completed } = req.body;
    const tasks = await readJson(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === req.params.id && t.userId === req.user.id);

    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Tarefa não encontrada.' });
    }

    let responsibleAvatar = tasks[taskIndex].responsibleAvatar;
    if (responsible && responsible !== tasks[taskIndex].responsible) {
      const parts = responsible.trim().split(' ');
      if (parts.length > 1) {
        responsibleAvatar = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      } else {
        responsibleAvatar = responsible.substring(0, 2).toUpperCase();
      }
    }

    const updatedTask = {
      ...tasks[taskIndex],
      title: title || tasks[taskIndex].title,
      description: description !== undefined ? description : tasks[taskIndex].description,
      responsible: responsible || tasks[taskIndex].responsible,
      responsibleAvatar,
      deadline: deadline !== undefined ? deadline : tasks[taskIndex].deadline,
      completed: completed !== undefined ? completed : tasks[taskIndex].completed,
      updatedAt: new Date().toISOString()
    };

    tasks[taskIndex] = updatedTask;
    await writeJson(TASKS_FILE, tasks);

    res.json(updatedTask);
  } catch (error) {
    console.error('Erro ao atualizar tarefa:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Atualizar status da tarefa
app.patch('/api/tasks/:id/status', authenticateJWT, async (req, res) => {
  try {
    const { status, completed } = req.body;
    
    if (!status && completed === undefined) {
      return res.status(400).json({ message: 'Status ou estado de conclusão é obrigatório.' });
    }

    const tasks = await readJson(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === req.params.id && t.userId === req.user.id);

    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Tarefa não encontrada.' });
    }

    if (status) tasks[taskIndex].status = status;
    if (completed !== undefined) tasks[taskIndex].completed = completed;
    
    tasks[taskIndex].updatedAt = new Date().toISOString();

    await writeJson(TASKS_FILE, tasks);

    res.json(tasks[taskIndex]);
  } catch (error) {
    console.error('Erro ao atualizar status:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Excluir tarefa
app.delete('/api/tasks/:id', authenticateJWT, async (req, res) => {
  try {
    const tasks = await readJson(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === req.params.id && t.userId === req.user.id);

    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Tarefa não encontrada.' });
    }

    tasks.splice(taskIndex, 1);
    await writeJson(TASKS_FILE, tasks);

    res.json({ message: 'Tarefa excluída com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir tarefa:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Tratar todas as outras rotas (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server rodando em http://localhost:${PORT}`);
});
