const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');

// Inicializando o banco de dados
const db = new sqlite3.Database('./db/events.db');

// Inicializando o app express
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração de sessão
app.use(session({
    store: new SQLiteStore,
    secret: 'teste_planner', // Substitua por um segredo seguro
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 dia
}));

// Servindo arquivos estáticos (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Criando as tabelas de eventos e usuários se não existirem
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        date TEXT NOT NULL,
        start_time TEXT,
        end_time TEXT,
        all_day INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// Rota para a página de login (sempre exibida na raiz '/')
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/login.html'));
});

// **Nova rota para a página de registro**
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/register.html'));
});

// Rota para registrar usuário
app.post('/register', (req, res) => {
    const { email, username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        db.run(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, [email, username, hash], function (err) {
            if (err) {
                return res.status(500).json({ error: "Usuário já registrado." });
            }
            req.session.userId = this.lastID;
            res.json({ message: 'Registrado com sucesso!' });
        });
    });
});


// Rota para login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.userId = user.id;
                res.json({ message: 'Login bem-sucedido!' });
            } else {
                res.status(401).json({ error: 'Credenciais inválidas.' });
            }
        });
    });
});

// Rota para logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao fazer logout.' });
        }
        res.json({ message: 'Logout realizado com sucesso!' });
    });
});

// Middleware para verificar se o usuário está autenticado
function checkAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/');
    }
}

// Rota para o planner (apenas para usuários autenticados)
app.get('/planner', checkAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/planner.html'));
});

// Rota para adicionar evento (apenas para usuários autenticados)
app.post('/add-event', checkAuthenticated, (req, res) => {
    const { title, description, date, start_time, end_time, all_day } = req.body;
    const userId = req.session.userId;
    db.run(`INSERT INTO events (user_id, title, description, date, start_time, end_time, all_day) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, title, description, date, start_time, end_time, all_day], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID });
        });
});

// Rota para buscar eventos (apenas para usuários autenticados)
app.get('/get-events', checkAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.all(`SELECT * FROM events WHERE user_id = ?`, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const events = rows.map(row => {
            return {
                id: row.id,
                title: row.title,
                description: row.description,
                start: row.all_day ? row.date : `${row.date}T${row.start_time}`,
                end: row.all_day ? null : `${row.date}T${row.end_time}`,
                allDay: !!row.all_day
            };
        });
        res.json(events);
    });
});

// Rota para obter o nome do usuário autenticado
app.get('/get-username', checkAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ username: row.username });
    });
});

// Rota para deletar evento (apenas para usuários autenticados)
app.post('/delete-event', checkAuthenticated, (req, res) => {
    const { id } = req.body;
    const userId = req.session.userId;

    // Certifique-se de que o evento pertence ao usuário logado
    db.run(`DELETE FROM events WHERE id = ? AND user_id = ?`, [id, userId], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes > 0) {
            res.json({ message: 'Evento excluído com sucesso!' });
        } else {
            res.status(404).json({ error: 'Evento não encontrado ou você não tem permissão para excluí-lo.' });
        }
    });
});

// Rota para atualizar evento (apenas para usuários autenticados)
app.post('/update-event', checkAuthenticated, (req, res) => {
    const { id, title, description, date, start_time, end_time, all_day } = req.body;
    const userId = req.session.userId;

    // Verificar se o evento pertence ao usuário logado e atualizar o evento
    db.run(`UPDATE events SET title = ?, description = ?, date = ?, start_time = ?, end_time = ?, all_day = ? WHERE id = ? AND user_id = ?`,
        [title, description, date, start_time, end_time, all_day, id, userId], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (this.changes > 0) {
                res.json({ message: 'Evento atualizado com sucesso!' });
            } else {
                res.status(404).json({ error: 'Evento não encontrado ou você não tem permissão para atualizá-lo.' });
            }
        });
});

// Iniciando o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
