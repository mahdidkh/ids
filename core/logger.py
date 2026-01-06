import json
import os
from datetime import datetime
from core.notifier import Notifier # On garde la notification Telegram

class LogManager:
    def __init__(self):
        # On calcule le dossier "logs" à la racine du projet
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(self.base_dir, "logs")
        self.log_file = os.path.join(self.log_dir, "attacks.json")

        # Mémoire des dernières attaques pour l'agrégation
        self.last_alerts = {}
        self.aggregation_window = 5  # secondes
        self.notifier = Notifier()

        # Créer le dossier logs s’il n’existe pas
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def log_alert(self, src_ip, attack_type, description):
        now = datetime.now()
        key = (src_ip, attack_type)

        # Si l'attaque existe déjà (agrégation)
        if key in self.last_alerts:
            last_time, count = self.last_alerts[key]

            # Si l’attaque revient rapidement (moins de 5s)
            if (now - last_time).total_seconds() < self.aggregation_window:
                count += 1
                self.last_alerts[key] = (now, count)

                # On écrit dans le fichier seulement tous les 10 messages pour ne pas ramer
                if count % 10 != 0:
                    return
            else:
                count = 1
        else:
            count = 1
            # Nouvelle attaque ! On envoie une notification Telegram
            self.notifier.send_notification(attack_type, src_ip, now.strftime("%Y-%m-%d %H:%M:%S"))

        # Sauvegarder l'état actuel des compteurs
        self.last_alerts[key] = (now, count)

        # Préparation de l'entrée JSON pour l'interface
        log_entry = {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), # Pour AlertsView
            "logged_at": now.strftime("%Y-%m-%d %H:%M:%S"), # Pour AttacksView
            "src_ip": src_ip if src_ip != "DNS_Server" else "192.168.1.1",
            "type": attack_type,
            "description": f"[Aggregated {count} times] {description}" if count > 1 else description,
            "count": count
        }

        self.write_json(log_entry)

    def log_attack(self, attack_data):
        # Utilisé pour les rapports d'attaques complets
        attack_data["logged_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.write_json(attack_data)

    def write_active_attacks(self, active_attacks_list):
        pass # Fonction gardée pour compatibilité mais non utilisée

    def write_json(self, entry):
        data = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except:
                data = []

        data.append(entry)
        
        # On garde seulement les 500 dernières alertes pour que le Dashboard reste rapide
        data = data[-500:]

        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
