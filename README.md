# ControlFinan (Rust)

![Rust](https://img.shields.io/badge/Rust-2024-000000?logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/Axum-0.8-7B3F00)
![Tailwind](https://img.shields.io/badge/Tailwind-4-06B6D4?logo=tailwindcss&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)

Aplicação web de controle financeiro pessoal, pensada para quem trabalha como motorista de aplicativo. Cada usuário registra entradas (créditos) e saídas (débitos) em contas como dinheiro, bancos e carteiras de aplicativos, e acompanha o saldo por dia e por mês.

Esta é a versão em **Rust** do [ControlFinan em Rails 8 + Hotwire](https://github.com/igorcb/controlfinan-rails8-hotwire). Ela tem **paridade de funcionalidades e de visual** com o original, assim como as versões em [Django](https://github.com/igorcb/controlfinan-django), [Laravel](https://github.com/igorcb/controlfinan-laravel), [Go](https://github.com/igorcb/controlfinan-go) e [Java](https://github.com/igorcb/controlfinan-java): mesmas telas, mesmas regras, mesmas mensagens e **mesmo esquema de banco**. As versões podem usar os mesmos dados, inclusive as senhas.

Stack: **Axum 0.8** (Tokio), **SQLx** para o Postgres, **Askama** para o HTML (templates compilados junto com o app) e o crate `bcrypt`.

## Funcionalidades

| Tela | Rota | O que faz |
|---|---|---|
| Conta Corrente | `/` | Lista os lançamentos, do mais recente para o mais antigo, 30 por página, com o saldo total |
| Saldo do dia | `/current_accounts?date=AAAA-MM-DD` | Filtra a listagem por um dia e mostra o saldo daquele dia |
| Novo lançamento | `/current_accounts/new` | Cadastra um crédito ou um débito |
| Detalhe, edição e exclusão | `/current_accounts/:id` | Mostra, altera ou remove um lançamento |
| Dashboard | `/dashboard` | Abas **Saldo Diário** e **Saldo Mensal** (corridas menos combustível, lavagem e telefone). As setas navegam entre os meses |
| JSON | `/current_accounts.json` e `/current_accounts/:id.json` | Os mesmos dados, para integrações |
| Cadastro, login e senha | `/registration/new`, `/session/new`, `/passwords/new` | Conta de usuário, com senha de no mínimo 6 caracteres |

Cada usuário só enxerga os próprios lançamentos.

## Como a paridade foi feita

| Rails 8 + Hotwire | Rust |
|---|---|
| Autenticação nativa do Rails 8 (`has_secure_password`, tabela `sessions`, cookie `session_id`) | Mesmo modelo: tabela `sessions` e cookie assinado `session_id`. As senhas usam bcrypt no formato do Rails (`$2a$`) |
| Proteção CSRF (`authenticity_token`) | Middleware que confere o token de cada POST, com o mesmo nome de campo |
| `rate_limit to: 10, within: 3.minutes` | Limite de 10 tentativas a cada 3 minutos por IP, em memória |
| Token de redefinição de senha (15 minutos) | Token assinado com validade de 15 minutos, invalidado quando a senha muda |
| `_method` para PATCH, PUT e DELETE | O mesmo campo `_method`, aplicado por um middleware antes do roteamento |
| Turbo (`data-turbo-confirm`) e Stimulus (abas) | JavaScript simples para a confirmação e as abas |
| jbuilder | JSON compacto com os mesmos campos e o mesmo formato (por exemplo, `"price":"150.0"`) |
| Tailwind CSS 4 | Tailwind CSS 4 (CLI standalone), com as mesmas classes |

Os valores em dinheiro usam `rust_decimal`.

**Verificação**, com o mesmo usuário e os mesmos dados (7.292 lançamentos) nos dois apps:

- Texto idêntico em todas as telas comparadas, incluindo paginação, filtro por dia, datas e meses inválidos, dashboard, formulários, mensagens de validação, erros de cadastro e login inválido.
- JSON idêntico byte a byte (lista, segunda página e detalhe).
- **14 telas idênticas pixel a pixel**: login, lista, filtro, dashboard, novo, detalhe e edição, no computador (1280 px) e no celular (390 px).
- Roteiro completo no navegador (Playwright), com 23 etapas: cadastro, login, lançamentos, edição, exclusão, dashboard, recuperação de senha e celular.

## Como rodar com Docker

```bash
docker compose up               # app em http://localhost:8005
```

O container de desenvolvimento compila o Tailwind e roda o app com `cargo run`. As tabelas são criadas na subida, com o mesmo esquema do app Rails. Depois de mudar código Rust ou templates, reinicie com `docker compose restart web`.

Imagem de produção: `Dockerfile.prod`, com o binário compilado em modo release num Debian mínimo (cerca de 81 MB). Configure `DATABASE_URL` e `SECRET_KEY_BASE` e, se quiser, `BCRYPT_COST` (padrão 12), `DB_POOL` (padrão 10) e `PORT` (padrão 8000).

## Testes

27 testes com `cargo test`: 3 de formatação e 24 de integração. Os de integração sobem o app numa porta aleatória e usam um cliente HTTP com cookies e um Postgres de verdade. Eles cobrem:

- Senha no formato do Rails, incluindo um hash gravado pelo próprio Rails.
- Validações em pt-BR, saldo e resumo do mês.
- Login, limite de tentativas, logout, CSRF, cadastro e redefinição de senha.
- Lançamentos: filtro, paginação, JSON, criar, editar, excluir e isolamento entre usuários.
- Dashboard.

```bash
docker compose exec web cargo test
```

Os testes usam o banco `controlfinan_rust_test`, criado automaticamente, e rodam um de cada vez porque compartilham o banco. O código passa no `cargo fmt` e no `cargo clippy` sem avisos.

## Estrutura

```
src/main.rs        configuração (variáveis de ambiente) e servidor
src/lib.rs         monta o app (middleware antes do roteador) e cria as tabelas
src/handlers.rs    rotas e handlers
src/web.rs         cookies assinados, sessão, CSRF, _method, flash e limite de tentativas
src/models.rs      usuários, sessões, lançamentos, validações e consultas
src/format.rs      moeda e decimais como no Rails
templates/         Askama com o mesmo HTML do app Rails
static/            JavaScript e ícones (o CSS é gerado pelo Tailwind)
tests/             testes de integração
```

## Benchmark

O benchmark com Rails, Django, Laravel, Go, Java, Rust, C#, Node.js e Elixir fica no repositório [controlfinan-rails8-hotwire](https://github.com/igorcb/controlfinan-rails8-hotwire/tree/main/benchmark).

## Licença

[MIT](LICENSE)
