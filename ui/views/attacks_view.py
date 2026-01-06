import flet as ft
from utils.data_handler import get_attacks, get_firewall_rules, save_firewall_rules
from core.firewall_manager import FirewallManager
import json

def AttacksView(page: ft.Page, nav):
    attacks = get_attacks()
    attacks.reverse()
    rules = get_firewall_rules()
    blocklist = rules.get("blocklist", [])
    
    # Functions
    def show_details(attack_data):
        def close_dlg(e):
            dlg.open = False
            page.update()

        # Severity color logic
        count = attack_data.get('count', 1)
        severity_color = ft.Colors.RED_400 if count > 10 else ft.Colors.ORANGE_400 if count > 1 else ft.Colors.BLUE_400

        dlg = ft.AlertDialog(
            shape=ft.RoundedRectangleBorder(radius=15),
            title=ft.Row([
                ft.Icon(ft.Icons.ANALYTICS_OUTLINED, color=ft.Colors.CYAN_200),
                ft.Text("Digital Forensic Report", size=20, weight=ft.FontWeight.BOLD)
            ], spacing=10),
            content=ft.Container(
                width=400,
                content=ft.Column([
                    ft.Divider(color=ft.Colors.GREY_800),
                    
                    # Attack Header
                    ft.Container(
                        padding=15,
                        bgcolor=ft.Colors.with_opacity(0.1, ft.Colors.WHITE),
                        border_radius=10,
                        content=ft.Column([
                            ft.Text("ATTACK SIGNATURE", size=10, color=ft.Colors.CYAN_200, weight=ft.FontWeight.BOLD),
                            ft.Text(attack_data.get('type', 'Unknown').upper(), size=24, weight=ft.FontWeight.BOLD, color=ft.Colors.RED_400),
                        ], spacing=0)
                    ),

                    ft.Divider(height=10, color=ft.Colors.TRANSPARENT),

                    # Data Grid
                    ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.ACCESS_TIME, size=16, color=ft.Colors.GREY_400),
                            ft.Text("Date/Time:", size=13, weight=ft.FontWeight.W_500, color=ft.Colors.GREY_400),
                            ft.Text(attack_data.get('logged_at') or attack_data.get('timestamp') or 'N/A', size=13, color=ft.Colors.WHITE)
                        ], spacing=10),
                        
                        ft.Row([
                            ft.Icon(ft.Icons.LAN_OUTLINED, size=16, color=ft.Colors.GREY_400),
                            ft.Text("Source IP:", size=13, weight=ft.FontWeight.W_500, color=ft.Colors.GREY_400),
                            ft.Text(attack_data.get('src_ip', 'Unknown'), size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_400)
                        ], spacing=10),
                        
                        ft.Row([
                            ft.Icon(ft.Icons.NUMBERS, size=16, color=ft.Colors.GREY_400),
                            ft.Text("Occurrences:", size=13, weight=ft.FontWeight.W_500, color=ft.Colors.GREY_400),
                            ft.Container(
                                content=ft.Text(f"{count} Events", size=11, weight=ft.FontWeight.BOLD),
                                padding=ft.padding.symmetric(horizontal=8, vertical=2),
                                bgcolor=severity_color,
                                border_radius=5
                            )
                        ], spacing=10),
                    ], spacing=12),

                    ft.Divider(color=ft.Colors.GREY_800),

                    # Description Section
                    ft.Text("INCIDENT DESCRIPTION", size=10, color=ft.Colors.GREY_500, weight=ft.FontWeight.BOLD),
                    ft.Container(
                        padding=10,
                        border=ft.border.all(1, ft.Colors.GREY_800),
                        border_radius=8,
                        content=ft.Text(attack_data.get('description', '-'), size=13, italic=True, color=ft.Colors.GREY_200)
                    ),
                    
                ], tight=True, spacing=15),
            ),
            actions=[
                ft.TextButton("Close Report", on_click=close_dlg, icon=ft.Icons.CHECK_CIRCLE_OUTLINE),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
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
            # Real Block (Windows)
            FirewallManager.block_ip(ip)
            
            rules["blocklist"].append(ip)
            save_firewall_rules(rules)
            page.snack_bar = ft.SnackBar(ft.Text(f"IP {ip} blocked & isolated!"), bgcolor=ft.Colors.RED_700)
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
            # Real Unblock (Windows)
            FirewallManager.unblock_ip(ip)
            
            rules["blocklist"].remove(ip)
            save_firewall_rules(rules)
            page.snack_bar = ft.SnackBar(ft.Text(f"IP {ip} restored."), bgcolor=ft.Colors.GREEN_700)
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
                alignment=ft.Alignment(0, 0),
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
                            alignment=ft.Alignment(0, 0)
                        ),
                        # Info Section
                        ft.Column([
                            ft.Text(f"{attack.get('type', 'Unknown Attack').upper()}", weight=ft.FontWeight.BOLD, color=ft.Colors.RED_100),
                            ft.Row([
                               ft.Icon(ft.Icons.LANGUAGE, size=12, color=ft.Colors.CYAN_200),
                               ft.Text(f"IP: {src_ip}", size=12, color=ft.Colors.GREY_400),
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
