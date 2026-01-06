import flet as ft
from utils.data_handler import get_alerts, get_attacks, get_firewall_rules

def HomeView(page: ft.Page, nav):
    # Fetch Data for Stats
    alerts = get_alerts()
    attacks = get_attacks()
    rules = get_firewall_rules()
    
    # 1. Hero Section with Gradient
    hero = ft.Container(
        content=ft.Column([
            ft.Text("SYSTEM COMMAND CENTER", size=14, weight=ft.FontWeight.W_500, color=ft.Colors.CYAN_200),
            ft.Text("Intrusion Detection System", size=45, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
            ft.Text("Monitoring, analyzing, and protecting your network in real-time.", size=16, color=ft.Colors.GREY_400),
        ], spacing=10),
        padding=40,
        width=page.window_width,
        border_radius=20,
        gradient=ft.LinearGradient(
            begin=ft.Alignment(-1, -1),
            end=ft.Alignment(1, 1),
            colors=[ft.Colors.GREY_900, ft.Colors.BLUE_900],
        ),
        shadow=ft.BoxShadow(spread_radius=1, blur_radius=15, color=ft.Colors.with_opacity(0.3, ft.Colors.BLACK))
    )

    # 2. System Status Indicator
    status_indicator = ft.Row([
        ft.Container(
            width=12, height=12, border_radius=6, 
            bgcolor=ft.Colors.GREEN_400,
            animate_scale=ft.Animation(1000, ft.AnimationCurve.EASE_IN_OUT),
        ),
        ft.Text("SYSTEM ONLINE & SECURE", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_400),
    ], spacing=10)

    # 3. Stats Section
    def create_stat_tile(label, value, icon, color):
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(icon, color=color, size=24),
                    ft.Text(label, size=12, color=ft.Colors.GREY_400, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text(value, size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=5),
            bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.WHITE),
            border=ft.border.all(1, ft.Colors.with_opacity(0.1, ft.Colors.WHITE)),
            border_radius=15,
            padding=20,
            expand=True,
            animate_scale=ft.Animation(300, ft.AnimationCurve.DECELERATE),
            on_hover=lambda e: setattr(e.control, "scale", 1.05 if e.data == "true" else 1.0),
        )

    stats_row = ft.Row([
        create_stat_tile("Total Alerts", str(len(alerts)), ft.Icons.WARNING_ROUNDED, ft.Colors.ORANGE_400),
        create_stat_tile("Threats", str(len(attacks)), ft.Icons.SECURITY_ROUNDED, ft.Colors.RED_400),
        create_stat_tile("Firewall Rules", str(len(rules.get('blocklist', [])) + len(rules.get('whitelist', []))), ft.Icons.BLOCK_ROUNDED, ft.Colors.CYAN_400),
    ], spacing=20)

    # 4. Quick Actions
    def create_action_card(title, desc, icon, index, color):
        return ft.Container(
            content=ft.Column([
                ft.Icon(icon, size=40, color=color),
                ft.Text(title, size=18, weight=ft.FontWeight.BOLD),
                ft.Text(desc, size=12, color=ft.Colors.GREY_400, text_align=ft.TextAlign.CENTER),
                ft.TextButton("Launch →", on_click=lambda _: nav(index)),
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
            bgcolor=ft.Colors.GREY_900,
            border_radius=15,
            padding=20,
            expand=True,
            border=ft.border.all(1, ft.Colors.GREY_800),
            on_hover=lambda e: setattr(e.control, "bgcolor", ft.Colors.with_opacity(0.1, color) if e.data == "true" else ft.Colors.GREY_900),
        )

    actions_row = ft.Row([
        create_action_card("Alerts Log", "Deep dive into system logs", ft.Icons.LIST_ALT, 1, ft.Colors.ORANGE_400),
        create_action_card("Attack Analysis", "Visualize incoming threats", ft.Icons.BAR_CHART_ROUNDED, 2, ft.Colors.RED_400),
        create_action_card("Firewall Manager", "Control network access", ft.Icons.SHIELD_ROUNDED, 3, ft.Colors.CYAN_400),
    ], spacing=20)

    return ft.Column([
        status_indicator,
        ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
        hero,
        ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
        ft.Text("SYSTEM OVERVIEW", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_500),
        stats_row,
        ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
        ft.Text("QUICK NAVIGATION", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_500),
        actions_row,
    ], scroll=ft.ScrollMode.ADAPTIVE, expand=True)
