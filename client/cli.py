import sys
import os

try:
    import typer
    import requests
    import segno
    import json
    from pathlib import Path
    from PIL import Image
    import questionary
    from rich.console import Console
    from rich.table import Table
    import tkinter as tk
    from tkinter import colorchooser
    from dotenv import load_dotenv
    
    # Load env from parent directory (url_shortener/.env) or current
    # Try explicit paths if general load fails finding the specific one? 
    # General load_dotenv() searches parents, so usually works if running from root.
    load_dotenv()
    load_dotenv(Path(__file__).parent.parent / ".env") 
except ImportError as e:
    print(f"❌ Error: Missing dependency '{e.name}'.")
    print("Please run the setup script to fix environment:")
    print("  ./setup_v7.sh")
    sys.exit(1)

# --- Config ---
SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8080") 
API_KEY = os.getenv("API_KEY", "changeme")
DOWNLOADS_DIR = Path.home() / "Downloads"

app = typer.Typer(add_completion=False)
console = Console()

def get_headers():
    return {"X-API-KEY": API_KEY, "Content-Type": "application/json"}

# --- Helpers ---
def shorten_with_isgd(url: str, slug: str, strategy: str) -> str:
    """Shortens the given URL using is.gd based on strategy."""
    base = "https://is.gd/create.php?format=json&url=" + url
    
    if strategy == "Match Internal" and slug:
        base += f"&shorturl={slug}"
    elif strategy == "Custom":
        custom_slug = questionary.text("Enter custom slug for is.gd:").ask()
        if custom_slug:
            base += f"&shorturl={custom_slug}"
    
    try:
        resp = requests.get(base, timeout=10)
        data = resp.json()
        if "shorturl" in data:
            return data["shorturl"]
        else:
            console.print(f"[yellow]is.gd warning: {data.get('errorcode', 'Unknown error')} - {data.get('errormessage', '')}[/yellow]")
            return url 
    except Exception as e:
        console.print(f"[red]is.gd failed: {e}[/red]")
        return url

def pick_color():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    color_code = colorchooser.askcolor(title="Choose QR Code Color")
    root.destroy()
    if color_code and color_code[1]: return color_code[1]
    return "black"

def create_link_flow():
    console.print(f"[bold cyan]--- Create New Link ---[/bold cyan]")
    url = questionary.text("Target URL:").ask()
    if not url: return

    # Payload setup
    payload = {"destination": url}
    
    slug = questionary.text("Custom Slug (optional):").ask()
    if slug: payload["slug"] = slug

    # Feature Selector (V8)
    features = questionary.checkbox(
        "Select Features to Enable:",
        choices=[
            "Targeting (iOS/Android)",
            "Protection (VPN/Bot Checking + Cloaking)",
            "Security (Password / Captcha)",
            "Limits (Expiration / Max Clicks)",
            "QR Code Generation"
        ]
    ).ask()
    
    if not features: features = []

    # 1. Targeting
    if "Targeting (iOS/Android)" in features:
        console.print("[cyan]--- Device Targeting ---[/cyan]")
        ios = questionary.text("iOS Destination URL (Empty to skip):").ask()
        if ios: payload["ios_url"] = ios
        
        android = questionary.text("Android Destination URL (Empty to skip):").ask()
        if android: payload["android_url"] = android

    # 2. Protection
    if "Protection (VPN/Bot Checking + Cloaking)" in features:
        console.print("[cyan]--- Protection & Cloaking ---[/cyan]")
        
        payload["block_vpn"] = questionary.confirm("Block VPNs?", default=False).ask()
        payload["block_bots"] = questionary.confirm("Block Bots/Crawlers?", default=True).ask()
        
        safe = questionary.text("Safe URL for Cloaking (Where to send blocked users?):", default="https://google.com").ask()
        if safe: payload["safe_url"] = safe

        # V9 No-JS Policy
        payload["allow_no_js"] = questionary.confirm("Allow users without JavaScript? (Less Stealth, More Reach)", default=False).ask()

    # 3. Security
    if "Security (Password / Captcha)" in features:
        console.print("[cyan]--- Access Control ---[/cyan]")
        sec_type = questionary.select(
            "Security Method:",
            choices=["Password", "Standalone Captcha", "Both", "None"]
        ).ask()
        
        if sec_type in ["Password", "Both"]:
            pw = questionary.password("Password:").ask()
            if pw: payload["password"] = pw
            
        if sec_type in ["Standalone Captcha", "Both"]:
             # If BOTH, force True without asking. If Standalone, ask confirmation (or just force True?)
             # User said: "if BOTH don't ask". So logic:
             if sec_type == "Both":
                 payload["enable_captcha"] = True
             elif questionary.confirm("Enable Cloudflare Captcha?", default=True).ask():
                payload["enable_captcha"] = True

    # 4. Limits
    if "Limits (Expiration / Max Clicks)" in features:
        console.print("[cyan]--- Usage Limits ---[/cyan]")
        clicks = questionary.text("Max Clicks (0 for unlimited):").ask()
        if clicks and clicks != "0": payload["max_clicks"] = int(clicks)

        expire = questionary.text("Expiration (minutes, 0 for unlimited):").ask()
        if expire and expire != "0": payload["expiration_minutes"] = int(expire)

    # API Call
    try:
        resp = requests.post(f"{SERVER_URL}/api/create", json=payload, headers=get_headers())
        if resp.status_code == 200:
            data = resp.json()
            internal_slug = data["slug"]
            internal_url = data["url"]
            console.print(f"[green]✔ Link Created![/green]")
            console.print(f"Internal: {internal_url}")
            
            # Masking is now DEFAULT
            strat = questionary.select("is.gd Masking Strategy:", choices=["Match Internal", "Random", "Custom", "Skip (Raw)"]).ask()
            if strat != "Skip (Raw)":
                 final_link = shorten_with_isgd(internal_url, strat, internal_slug)
                 console.print(f"[bold green]Public URL: {final_link}[/bold green]")
            else:
                 console.print(f"[bold green]Public URL: {internal_url}[/bold green]")

            # QR Code Generation (Based on Feature Selection)
            if "QR Code Generation" in features:
                 color = questionary.select("QR Color:", choices=["black", "blue", "red", "green"]).ask()
                 qr = qrcode.QRCode(box_size=10, border=4)
                 qr.add_data(internal_url) # Always QR the internal logic URL (or public?) - Internal usually safer for tracking 
                 qr.make(fit=True)
                 
                 img = qr.make_image(fill_color=color, back_color="white")
                 if not os.path.exists(DOWNLOADS_DIR): os.makedirs(DOWNLOADS_DIR)
                 filename = DOWNLOADS_DIR / f"qr_{internal_slug}.png"
                 img.save(filename)
                 console.print(f"[green]QR Saved: {filename}[/green]")
                 if sys.platform == "darwin": os.system(f"open '{filename}'")

        else:
            console.print(f"[red]Error: {resp.text}[/red]")
    except Exception as e:
        console.print(f"[red]Connection Error: {e}[/red]")

def get_slug_list():
    """Helper to fetch list of slugs from server."""
    try:
        resp = requests.get(f"{SERVER_URL}/api/links", headers=get_headers())
        if resp.status_code == 200:
            links = resp.json()
            if not links: return []
            return [f"{l['slug']} -> {l['destination']}" for l in links] + ["[🔙 BACK]"]
    except:
        return ["[🔙 BACK]"]
    return []

def stats_flow():
     slugs = get_slug_list()
     choices = ["ALL (Everything)"] + slugs
     
     selection = questionary.select("Select Link for Stats:", choices=choices).ask()
     if not selection or selection == "[🔙 BACK]": return
     
     params = {}
     if selection != "ALL (Everything)":
         # Parse slug from "slug -> dest" string
         real_slug = selection.split(" -> ")[0]
         params['slug'] = real_slug
     
     try:
        resp = requests.get(f"{SERVER_URL}/api/stats", params=params, headers=get_headers())
        if resp.status_code == 200:
             dest = DOWNLOADS_DIR / "stats_export.csv"
             with open(dest, 'wb') as f: f.write(resp.content)
             console.print(f"[green]Stats downloaded: {dest}[/green]")
             if sys.platform == "darwin": os.system(f"open '{dest}'")
        else:
             console.print(f"[red]Error: {resp.text}[/red]")
     except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")

def edit_flow():
    slugs = get_slug_list()
    if not slugs:
        console.print("[yellow]No links found to edit.[/yellow]")
        return

    selection = questionary.select("Select Link to Edit:", choices=slugs).ask()
    if not selection or selection == "[🔙 BACK]": return
    slug = selection.split(" -> ")[0]
    
    action = questionary.select("What to update?", choices=["Destination URL", "Max Clicks", "Password", "Delete Link", "[🔙 BACK]"]).ask()
    
    if action == "[🔙 BACK]" or not action:
        return

    if action == "Delete Link":
        if questionary.confirm(f"Really delete {slug}?", default=False).ask():
            requests.delete(f"{SERVER_URL}/api/links/{slug}", headers=get_headers())
            console.print("Deleted.")
        return

    payload = {}
    if action == "Destination URL":
        payload["destination"] = questionary.text("New URL:").ask()
    elif action == "Max Clicks":
        payload["max_clicks"] = int(questionary.text("New Limit:").ask())
    elif action == "Password":
        payload["password"] = questionary.password("New Password (empty to remove):").ask()

    if payload:
        resp = requests.patch(f"{SERVER_URL}/api/links/{slug}", json=payload, headers=get_headers())
        if resp.status_code == 200:
            console.print("[green]Updated![/green]")
        else:
            console.print(f"[red]Failed: {resp.text}[/red]")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Interactive Menu URL Shortener."""
    # If user passed a command (like 'add'), let Typer handle it via subcommands (not implemented here)
    # But since we want "Interactive First", we just trap the loop if no subcommand.
    if ctx.invoked_subcommand is None:
        console.print("[bold yellow]PythonAnywhere URL Shortener V7[/bold yellow]")
        while True:
            choice = questionary.select(
                "Main Menu",
                choices=["Create Link", "Manage Link (Edit/Delete)", "Stats (Export)", "Exit"]
            ).ask()
            
            if choice == "Create Link":
                create_link_flow()
            elif choice == "Manage Link (Edit/Delete)":
                edit_flow()
            elif choice == "Stats (Export)":
                stats_flow()
            elif choice == "Exit":
                console.print("Bye! 👋")
                break
            elif choice is None: # Ctrl+C
                break

if __name__ == "__main__":
    app()
