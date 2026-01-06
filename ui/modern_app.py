import flet as ft
import os
import sys
import threading
import time

# Teacher says: This part is CRITICAL to find the 'core' folder!
# We add the parent directory (project root) to Python's search list.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from views.home_view import HomeView
from views.alerts_view import AlertsView
from views.attacks_view import AttacksView
from views.firewall_view import FirewallView

def main(page: ft.Page):
    page.title = "Mini IDS - Modern Dashboard"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window_width = 1200
    page.window_height = 800
    
    # Define color scheme
    # Primary: Electric Blue / Purple
    # Background: Dark Gray / Black
    
    # Safe Theme
    page.theme = ft.Theme(
        color_scheme_seed=ft.Colors.CYAN,
        visual_density=ft.VisualDensity.COMFORTABLE,
    )

    # --- Navigation ---
    
    content_container = ft.Container(expand=True, padding=20)
    
    def change_view(selected_index):
        # Sync NavigationRail
        rail.selected_index = selected_index
        
        if selected_index == 0:
            content_container.content = HomeView(page, change_view)
        elif selected_index == 1:
            content_container.content = AlertsView(page)
        elif selected_index == 2:
            content_container.content = AttacksView(page, change_view)
        elif selected_index == 3:
            content_container.content = FirewallView(page)
        page.update()

    def on_rail_change(e):
        change_view(e.control.selected_index)

    rail = ft.NavigationRail(
        selected_index=0,
        label_type=ft.NavigationRailLabelType.ALL,
        min_width=100,
        min_extended_width=400,
        group_alignment=-0.9,
        destinations=[
            ft.NavigationRailDestination(
                icon=ft.Icons.HOME_ROUNDED, 
                selected_icon=ft.Icons.HOME_ROUNDED, 
                label="Home"
            ),
            ft.NavigationRailDestination(
                icon=ft.Icons.WARNING_AMBER_ROUNDED, 
                selected_icon=ft.Icons.WARNING_ROUNDED, 
                label="Alerts"
            ),
            ft.NavigationRailDestination(
                icon=ft.Icons.SECURITY_ROUNDED, 
                selected_icon=ft.Icons.SHIELD_ROUNDED, 
                label="Attacks"
            ),
            ft.NavigationRailDestination(
                icon=ft.Icons.BLOCK_ROUNDED, 
                selected_icon=ft.Icons.ADMIN_PANEL_SETTINGS_ROUNDED, 
                label="Firewall"
            ),
        ],
        on_change=on_rail_change,
        bgcolor=ft.Colors.GREY_900,
    )

    # Main Layout
    layout = ft.Row(
        [
            rail,
            ft.VerticalDivider(width=1, color=ft.Colors.GREY_800),
            content_container
        ],
        expand=True,
    )

    page.add(layout)
    
    # --- Auto-Refresh ---
    from utils.data_handler import get_alerts, get_attacks
    page.last_alert_count = len(get_alerts())
    page.last_attack_count = len(get_attacks())

    def update_data():
        while True:
            try:
                # 1. Fetch current data counts
                current_alerts = get_alerts()
                current_attacks = get_attacks()
                
                alert_count = len(current_alerts)
                attack_count = len(current_attacks)
                
                has_new_data = False
                
                # 2. Handle Notifications (New Alerts)
                if alert_count > page.last_alert_count:
                    new_alert = current_alerts[0] # newest first
                    page.snack_bar = ft.SnackBar(
                        content=ft.Text(f"🚨 New Threat: {new_alert.get('type')} from {new_alert.get('src_ip')}"),
                        bgcolor=ft.Colors.RED_700
                    )
                    page.snack_bar.open = True
                    page.last_alert_count = alert_count
                    has_new_data = True
                
                # Check if attacks increased
                if attack_count > page.last_attack_count:
                    page.last_attack_count = attack_count
                    has_new_data = True

                # 3. Only refresh UI if there is new data & not on Firewall page (index 3 now)
                if has_new_data:
                    if rail.selected_index != 3:
                        # Refresh current view
                        if rail.selected_index == 0:
                            content_container.content = HomeView(page, change_view)
                        elif rail.selected_index == 1:
                            content_container.content = AlertsView(page)
                        elif rail.selected_index == 2:
                            content_container.content = AttacksView(page, change_view)
                        page.update()
                    else:
                        page.update() # Just update notifications bar
            except Exception as e:
                print(f"Update error: {e}")
            
            time.sleep(5)

    threading.Thread(target=update_data, daemon=True).start()

    # Initialize
    change_view(0)

if __name__ == "__main__":
    ft.app(main)
