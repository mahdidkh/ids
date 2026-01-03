import flet as ft
from utils.data_handler import get_attacks, get_geo_info, get_firewall_rules, save_firewall_rules
import json

def AttacksView(page: ft.Page, nav):
    attacks = get_attacks()
    attacks.reverse()
    rules = get_firewall_rules()
    blocklist = rules.get("blocklist", [])
    
    # Functions
    def show_details(attack_data):
        print(f"DEBUG: Details button clicked for {attack_data.get('type')}")
        
        def close_dlg(e):
            dlg.open = False
            page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Attack Report Details"),
            content=ft.Text(json.dumps(attack_data, indent=2), size=11),
            actions=[
                ft.TextButton("Close", on_click=close_dlg),
            ],
        )
        
        # Overlay approach is more robust in some Flet versions
        if dlg not in page.overlay:
            page.overlay.append(dlg)
        
        dlg.open = True
        page.update()
        print("DEBUG: Dialog show command sent")

    def block_ip(ip):
        rules = get_firewall_rules()
        if ip not in rules["blocklist"]:
            rules["blocklist"].append(ip)
            save_firewall_rules(rules)
            page.snack_bar = ft.SnackBar(ft.Text(f"IP {ip} blocked successfully!"), bgcolor=ft.Colors.RED_700)
            page.snack_bar.open = True
            page.update()
            # Refresh view to show Unblock button
            nav(2) # Instant UI Refresh
        else:
            page.snack_bar = ft.SnackBar(ft.Text(f"IP {ip} is already blocked."))
            page.snack_bar.open = True
            page.update()

    def unblock_ip(ip):
        rules = get_firewall_rules()
        if ip in rules["blocklist"]:
            rules["blocklist"].remove(ip)
            save_firewall_rules(rules)
            page.snack_bar = ft.SnackBar(ft.Text(f"IP {ip} unblocked!"), bgcolor=ft.Colors.GREEN_700)
            page.snack_bar.open = True
            page.update()
            # Refresh
            nav(2)
        else:
            page.update()

    # Header
    header = ft.Row([
        ft.Icon(ft.Icons.SHIELD_ROUNDED, size=30, color=ft.Colors.RED_400),
        ft.Text("Detected Attacks", size=30, weight=ft.FontWeight.BOLD),
    ])

    if not attacks:
        return ft.Column([
            header,
            ft.Divider(),
            ft.Container(
                content=ft.Text("No attacks recorded yet.", size=20, color=ft.Colors.GREY_500),
                alignment=ft.alignment.center,
                expand=True
            )
        ], expand=True)

    # Cards Grid
    grid = ft.GridView(
        expand=True,
        runs_count=1,
        max_extent=500,
        child_aspect_ratio=3.0,
        spacing=10,
        run_spacing=10,
    )

    for attack in attacks:
        src_ip = attack.get("src_ip", "Unknown")
        geo = get_geo_info(src_ip)
        
        # Severity Color
        card_color = ft.Colors.GREY_900
        border_color = ft.Colors.GREY_700
        
        count = attack.get("count", 1)
        if count > 100:
             border_color = ft.Colors.RED_500
        elif count > 10:
             border_color = ft.Colors.ORANGE_500
             
        # Actions logic
        is_blocked = src_ip in blocklist

        grid.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        # Icon Section
                        ft.Container(
                            content=ft.Icon(ft.Icons.SECURITY, color=ft.Colors.RED_200, size=40),
                            padding=10,
                            alignment=ft.alignment.center
                        ),
                        # Info Section
                        ft.Column([
                            ft.Text(f"{attack.get('type', 'Unknown Attack').upper()}", weight=ft.FontWeight.BOLD, color=ft.Colors.RED_100),
                            ft.Row([
                               ft.Text(f"{geo['flag']} {geo['country']}", size=12, color=ft.Colors.CYAN_200),
                               ft.Text(f"• IP: {src_ip}", size=12, color=ft.Colors.GREY_400),
                            ]),
                            ft.Text(f"Count: {count} | Last: {attack.get('logged_at', '')}", size=10, color=ft.Colors.GREY_500),
                        ], alignment=ft.MainAxisAlignment.CENTER, spacing=2, expand=True),
                    ]),
                    # Actions Section
                    ft.Row([
                        ft.TextButton(
                            "Details", 
                            icon=ft.Icons.INFO_OUTLINE,
                            icon_color=ft.Colors.BLUE_400,
                            on_click=lambda _, a=attack: show_details(a)
                        ),
                        ft.TextButton(
                            "Unblock" if is_blocked else "Block IP", 
                            icon=ft.Icons.SHIELD_OUTLINED if is_blocked else ft.Icons.BLOCK,
                            icon_color=ft.Colors.GREEN_400 if is_blocked else ft.Colors.RED_400,
                            on_click=lambda _, ip=src_ip, b=is_blocked: unblock_ip(ip) if b else block_ip(ip)
                        ),
                    ], alignment=ft.MainAxisAlignment.END, spacing=0)
                ], tight=True),
                bgcolor=card_color,
                border=ft.border.all(1, border_color),
                border_radius=10,
                padding=10,
                animate_scale=ft.Animation(300, ft.AnimationCurve.DECELERATE),
                on_hover=lambda e: setattr(e.control, "scale", 1.02 if e.data == "true" else 1.0),
            )
        )

    return ft.Column(
        [
            header,
            # Stats Bar
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Text("Threats", size=12, color=ft.Colors.RED_200),
                        ft.Text(str(len(attacks)), size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    bgcolor=ft.Colors.GREY_900, padding=10, border_radius=10, expand=True
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("Peak Intensity", size=12, color=ft.Colors.ORANGE_200),
                        ft.Text(str(max((a.get('count', 1) for a in attacks), default=0)), size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    bgcolor=ft.Colors.GREY_900, padding=10, border_radius=10, expand=True
                ),
            ], spacing=10),
            ft.Divider(),
            ft.Container(grid, expand=True)
        ],
        expand=True
    )
