import flet as ft
from utils.data_handler import get_alerts

def AlertsView(page: ft.Page):
    # Fetch Data
    alerts = get_alerts()
    alerts.reverse() # Show newest first
    
    # Define Columns
    columns = [
        ft.DataColumn(ft.Text("Timestamp")),
        ft.DataColumn(ft.Text("Source IP")),
        ft.DataColumn(ft.Text("Type")),
        ft.DataColumn(ft.Text("Description"), numeric=False),
    ]
    
    # Create Rows
    rows = []
    for alert in alerts:
        # Determine color based on severity (simple keyword matching)
        c = ft.Colors.WHITE
        if "BLOCK" in alert.get('description', '') or "Flood" in alert.get('type', ''):
            c = ft.Colors.RED_200
        elif "Scan" in alert.get('type', ''):
            c = ft.Colors.ORANGE_200
            
        rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(alert.get('timestamp', 'N/A'), color=c)),
                    ft.DataCell(ft.Text(alert.get('src_ip', 'N/A'), color=c, weight=ft.FontWeight.BOLD)),
                    ft.DataCell(ft.Text(alert.get('type', 'Unknown'), color=c)),
                    ft.DataCell(ft.Text(alert.get('description', '-'), color=c, size=12, overflow=ft.TextOverflow.ELLIPSIS)),
                ]
            )
        )
        
    # If no data
    if not rows:
        return ft.Column([
            ft.Text("Alerts Dashboard", size=30, weight=ft.FontWeight.BOLD),
            ft.Container(
                content=ft.Text("No alerts found.", size=20, color=ft.Colors.GREY_500),
                alignment=ft.alignment.center,
                expand=True
            )
        ], expand=True)

    # Table Container with Scroll
    table = ft.DataTable(
        columns=columns,
        rows=rows,
        border=ft.border.all(1, ft.Colors.GREY_800),
        vertical_lines=ft.border.BorderSide(1, ft.Colors.GREY_800),
        horizontal_lines=ft.border.BorderSide(1, ft.Colors.GREY_800),
        heading_row_color=ft.Colors.GREY_900,
        heading_text_style=ft.TextStyle(weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_200),
        column_spacing=20,
    )
    
    return ft.Column(
        [
            ft.Row([
                ft.Icon(ft.Icons.WARNING_ROUNDED, size=30, color=ft.Colors.ORANGE_400),
                ft.Text("Alerts Dashboard", size=30, weight=ft.FontWeight.BOLD),
            ]),
            # Stats Bar
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Text("Total Logs", size=12, color=ft.Colors.CYAN_200),
                        ft.Text(str(len(rows)), size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    bgcolor=ft.Colors.GREY_900, padding=10, border_radius=10, expand=True
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("Critical", size=12, color=ft.Colors.RED_200),
                        ft.Text(str(sum(1 for r in alerts if "BLOCK" in r.get('description', '') or "Flood" in r.get('type', ''))), size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    bgcolor=ft.Colors.GREY_900, padding=10, border_radius=10, expand=True
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("Unique IPs", size=12, color=ft.Colors.PURPLE_200),
                        ft.Text(str(len(set(r.get('src_ip') for r in alerts))), size=20, weight=ft.FontWeight.BOLD),
                    ]),
                    bgcolor=ft.Colors.GREY_900, padding=10, border_radius=10, expand=True
                ),
            ], spacing=10),
            ft.Divider(),
            ft.Container(
                content=ft.Column([table], scroll=ft.ScrollMode.ALWAYS),
                expand=True,
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=10
            )
        ],
        expand=True
    )
