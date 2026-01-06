import flet as ft
from utils.data_handler import get_firewall_rules, save_firewall_rules
from core.firewall_manager import FirewallManager

def FirewallView(page: ft.Page):
    # State
    rules = get_firewall_rules()
    blocklist = rules.get("blocklist", [])
    whitelist = rules.get("whitelist", [])
    
    # Input Field
    ip_input = ft.TextField(label="IP Address", hint_text="192.168.1.X", width=300, bgcolor=ft.Colors.GREY_800)
    
    def refresh_tables():
         blocklist_table.rows.clear()
         whitelist_table.rows.clear()
         
         for ip in blocklist:
             blocklist_table.rows.append(
                 ft.DataRow(cells=[
                     ft.DataCell(ft.Text(ip, color=ft.Colors.RED_200)),
                     ft.DataCell(ft.IconButton(ft.Icons.DELETE, on_click=lambda e, ip=ip: remove_ip(ip, "block")))
                 ])
             )

         for ip in whitelist:
             whitelist_table.rows.append(
                 ft.DataRow(cells=[
                     ft.DataCell(ft.Text(ip, color=ft.Colors.GREEN_200)),
                     ft.DataCell(ft.IconButton(ft.Icons.DELETE, on_click=lambda e, ip=ip: remove_ip(ip, "white")))
                 ])
             )
         page.update()

    def add_to_blocklist(e):
        if ip_input.value and ip_input.value not in blocklist:
            # Real Block (Windows)
            FirewallManager.block_ip(ip_input.value)
            
            blocklist.append(ip_input.value)
            save_all()
            ip_input.value = ""
            refresh_tables()
            
    def add_to_whitelist(e):
         if ip_input.value and ip_input.value not in whitelist:
            whitelist.append(ip_input.value)
            save_all()
            ip_input.value = ""
            refresh_tables()

    def remove_ip(ip, list_type):
        if list_type == "block" and ip in blocklist:
            # Real Unblock (Windows)
            FirewallManager.unblock_ip(ip)
            blocklist.remove(ip)
        elif list_type == "white" and ip in whitelist:
            whitelist.remove(ip)
        save_all()
        refresh_tables()

    def save_all():
        save_firewall_rules({"blocklist": blocklist, "whitelist": whitelist})
        
    # Tables
    blocklist_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Blocked IP")),
            ft.DataColumn(ft.Text("Action")),
        ],
        rows=[]
    )
    
    whitelist_table = ft.DataTable(
        columns=[
             ft.DataColumn(ft.Text("Whitelisted IP")),
             ft.DataColumn(ft.Text("Action")),
        ],
         rows=[]
    )
    
    refresh_tables()

    return ft.Column(
        [
             ft.Row([
                ft.Icon(ft.Icons.SECURITY, size=30, color=ft.Colors.CYAN_400),
                ft.Text("Firewall Control Center", size=30, weight=ft.FontWeight.BOLD),
            ]),
            ft.Divider(),
            
            # Action Bar
            ft.Row([
                ip_input,
                ft.ElevatedButton("Block", icon=ft.Icons.BLOCK, bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE, on_click=add_to_blocklist),
                ft.ElevatedButton("Allow", icon=ft.Icons.CHECK_CIRCLE, bgcolor=ft.Colors.GREEN_700, color=ft.Colors.WHITE, on_click=add_to_whitelist),
            ], spacing=20),
            
            ft.Divider(height=30),
            
            ft.Row([
                # Blocklist Column
                ft.Container(
                     content=ft.Column([
                         ft.Text("Blocklist (Deny All)", color=ft.Colors.RED_400, weight=ft.FontWeight.BOLD),
                         blocklist_table
                     ], scroll=ft.ScrollMode.ADAPTIVE),
                     expand=True,
                     bgcolor=ft.Colors.GREY_900,
                     border_radius=10,
                     padding=10
                ),
                
                # Whitelist Column
                ft.Container(
                     content=ft.Column([
                         ft.Text("Whitelist (Allow Trusted)", color=ft.Colors.GREEN_400, weight=ft.FontWeight.BOLD),
                         whitelist_table
                     ], scroll=ft.ScrollMode.ADAPTIVE),
                     expand=True,
                     bgcolor=ft.Colors.GREY_900,
                     border_radius=10,
                     padding=10
                )
            ], expand=True, spacing=20)
        ],
        expand=True
    )
