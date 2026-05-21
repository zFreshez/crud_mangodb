const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'segredo', resave: false, saveUninitialized: false }));

// Conecta ao MongoDB local
mongoose.connect('mongodb://localhost:27017/site_simples')
    .then(() => console.log('MongoDB Conectado com sucesso!'))
    .catch(err => console.error('Erro ao conectar ao MongoDB. Certifique-se de que ele está aberto:', err));

const Usuario = mongoose.model('Usuario', new mongoose.Schema({
    nome: String, email: { type: String, unique: true }, senha: String
}));

function proteger(req, res, next) {
    if (req.session.usuarioId) return next();
    res.redirect('/login');
}

app.get('/registrar', (req, res) => res.render('registrar'));
app.post('/registrar', async (req, res) => {
    const hash = await bcrypt.hash(req.body.senha, 10);
    await Usuario.create({ nome: req.body.nome, email: req.body.email, senha: hash });
    res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    const user = await Usuario.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.senha, user.senha)) {
        req.session.usuarioId = user._id;
        req.session.usuarioNome = user.nome;
        return res.redirect('/dashboard');
    }
    res.send('Dados incorretos. <a href="/login">Tentar novamente</a>');
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/dashboard', proteger, async (req, res) => {
    const lista = await Usuario.find();
    res.render('dashboard', { nome: req.session.usuarioNome, lista });
});

app.post('/editar/:id', proteger, async (req, res) => {
    await Usuario.findByIdAndUpdate(req.params.id, { nome: req.body.nome, email: req.body.email });
    res.redirect('/dashboard');
});

app.get('/deletar/:id', proteger, async (req, res) => {
    await Usuario.findByIdAndDelete(req.params.id);
    res.redirect('/dashboard');
});

app.get('/', (req, res) => res.redirect('/login'));
app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000'));