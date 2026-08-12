# digital-library
O projeto pensado é uma plataforma de estudos e organização digital, onde os usuarios poderão procurar por livros digitais de seu interesse para estudos e pesquisa academica, o projeto não visa armazenar livros de direitos autorais externos, a ideia é fazer a pesquisa em APIs públicas e redirecionar o estudante para o site de origem.


## Stack

* **Linguagem:** Python
* **Framework:** Django, bootstrap
* **API:** Django REST Framework
* **Banco de dados:** PostgreSQL
* **Versionamento:** Git e GitHub

## Arquitetura

O projeto utilizará uma **Arquitetura em Camadas**, buscando separar as responsabilidades do sistema e facilitar sua manutenção e evolução.

A estrutura será organizada principalmente em:

```text
Interface
    ↓
Controllers
    ↓
Services
    ↓
Repositories / Integrações
    ↓
PostgreSQL / APIs externas
```

### Controllers

Responsáveis por receber as requisições e encaminhá-las para as regras de negócio.

### Services

Aqui ficarão as regras de negócio da aplicação, como busca, filtros, favoritos e gerenciamento dos materiais.

### Repositories

Responsáveis pelo acesso e persistência dos dados no banco de dados.

### Integrações

Camada responsável pela comunicação com APIs externas, como por exemplo Google Books e Open Library, mantendo essa lógica separada do restante da aplicação.

Essa estrutura permite que diversas fontes de livros sejam utilizadas sem que as regras de negócio dependam diretamente de uma API específica.

## MVP 1

A primeira versão terá como foco:

* Cadastro e login de usuários (envolvendo os principais requisitos de autenticação e autorização;
* Busca de livros e materiais;
* Filtros por assunto e categoria;
* Visualização das informações dos materiais;
* Acesso à fonte oficial do conteúdo;
* Favoritos;

Estrutura do projeto

```text
src/
├── apps/
│   ├── accounts/
│   ├── library/
│   ├── favorites/
│   ├── history/
│   └── reviews/
│
├── services/
│   ├── book_service.py
│   ├── favorite_service.py
│   └── review_service.py
│
├── repositories/
│   ├── book_repository.py
│   └── favorite_repository.py
│
├── integrations/
│   ├── google_books/
│   │   └── client.py
│   │
│   └── open_library/
│       └── client.py
│
├── config/
│
└── manage.py
```

A pasta `docs/` contém os documentos de requisitos, escopo e arquitetura do projeto.

## Status

**Em desenvolvimento — MVP 1**

## Autor

**Davi Eliote de Carvalho**

Projeto acadêmico — Engenharia de Software.
