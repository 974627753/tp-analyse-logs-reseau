def lire_logs(nom_fichier):
    """
    Lit le fichier de logs et retourne une liste de dicts.
    Chaque dict représente une entrée : {'date': str, 'heure': str, 'ip': str, 'port': int, 'protocole': str, 'statut': str}
    """
    entrees = []
    try:
        with open(nom_fichier, 'r', encoding='utf-8') as fichier:
            for ligne in fichier:
                ligne = ligne.strip()
                if not ligne:
                    continue
                parties = ligne.split(';')
                if len(parties) == 6:
                    entree = {
                        'date': parties[0],
                        'heure': parties[1],
                        'ip': parties[2],
                        'port': int(parties[3]),
                        'protocole': parties[4],
                        'statut': parties[5]
                    }
                    entrees.append(entree)
    except FileNotFoundError:
        print(f"Erreur : Fichier {nom_fichier} non trouvé.")
        return []
    return entrees



if __name__ == "__main__":
    logs = lire_logs('network_log.txt')
    print(f"Nombre total d'entrées lues : {len(logs)}")
    if logs:
        print("Exemple d'entrée :", logs[0])
from collections import Counter

def calculer_stats(entrees):
    """
    Calcule les stats : total, succès, échecs, port max, IP max.
    Retourne un dict avec ces infos.
    """
    if not entrees:
        return {}
    
    total_connexions = len(entrees)
    succes = sum(1 for e in entrees if e['statut'] == 'SUCCES')
    echecs = total_connexions - succes
    
    ports = Counter(e['port'] for e in entrees)
    port_max = ports.most_common(1)[0] if ports else (0, 0)
    
    ips = Counter(e['ip'] for e in entrees)
    ip_max = ips.most_common(1)[0] if ips else ('', 0)
    
    return {
        'total_connexions': total_connexions,
        'succes': succes,
        'echecs': echecs,
        'port_plus_utilise': port_max[0],
        'port_plus_utilise_count': port_max[1],
        'ip_plus_active': ip_max[0],
        'ip_plus_active_count': ip_max[1]
    }



if __name__ == "__main__":
    logs = lire_logs('network_log.txt')
    stats = calculer_stats(logs)
    print("Statistiques :")
    for cle, valeur in stats.items():
        print(f"{cle}: {valeur}")

def detecter_suspectes(entrees):
    """
    Détecte les IP avec >5 échecs sur un même port.
    Retourne une liste de tuples (ip, port, count_echecs).
    """
    echecs_par_ip_port = {}
    for e in entrees:
        if e['statut'] == 'ECHEC':
            ip = e['ip']
            port = e['port']
            if ip not in echecs_par_ip_port:
                echecs_par_ip_port[ip] = Counter()
            echecs_par_ip_port[ip][port] += 1
    
    suspectes = []
    for ip, counts in echecs_par_ip_port.items():
        for port, count in counts.items():
            if count > 5:
                suspectes.append((ip, port, count))
    
    return suspectes




if __name__ == "__main__":
    logs = lire_logs('network_log.txt')
    stats = calculer_stats(logs)
    suspectes = detecter_suspectes(logs)
    
    print("\n=== STATISTIQUES ===")
    print(f"Total connexions : {stats['total_connexions']}")
    print(f"Succès : {stats['succes']}")
    print(f"Échecs : {stats['echecs']}")
    print(f"Port le plus utilisé : {stats['port_plus_utilise']} ({stats['port_plus_utilise_count']} fois)")
    print(f"IP la plus active : {stats['ip_plus_active']} ({stats['ip_plus_active_count']} fois)")
    
    print("\n=== ACTIVITÉS SUSPECTES ===")
    if suspectes:
        for ip, port, count in suspectes:
            print(f"ALERTE : IP {ip} a {count} échecs sur port {port}")
    else:
        print("Aucune activité suspecte détectée.")



def generer_rapport(stats, suspectes, entrees, nom_fichier='rapport_analyse.txt'):
    """
    Génère un fichier rapport structuré.
    """
    ports = Counter(e['port'] for e in entrees)
    top_ports = ports.most_common(3)
    
    with open(nom_fichier, 'w', encoding='utf-8') as f:
        f.write("RAPPORT D'ANALYSE DES LOGS RÉSEAU\n")
        f.write("=" * 40 + "\n\n")
        f.write("RÉSUMÉ DES STATISTIQUES\n")
        f.write("-" * 20 + "\n")
        f.write(f"Date d'analyse : 2026-02-13\n")  # Date actuelle
        f.write(f"Total connexions analysées : {stats['total_connexions']}\n")
        f.write(f"Connexions réussies : {stats['succes']}\n")
        f.write(f"Connexions échouées : {stats['echecs']}\n")
        f.write(f"Port le plus utilisé : {stats['port_plus_utilise']} ({stats['port_plus_utilise_count']} occurrences)\n")
        f.write(f"Adresse IP la plus active : {stats['ip_plus_active']} ({stats['ip_plus_active_count']} occurrences)\n\n")
        
        f.write("ACTIVITÉS SUSPECTES DÉTECTÉES\n")
        f.write("-" * 30 + "\n")
        if suspectes:
            for ip, port, count in suspectes:
                f.write(f"IP suspecte : {ip} - {count} échecs sur port {port}\n")
        else:
            f.write("Aucune IP suspecte identifiée.\n\n")
        
        f.write("TOP 3 DES PORTS LES PLUS UTILISÉS\n")
        f.write("-" * 30 + "\n")
        for i, (port, count) in enumerate(top_ports, 1):
            f.write(f"{i}. Port {port} : {count} occurrences\n")
    
    print(f"\nRapport généré : {nom_fichier}")



if __name__ == "__main__":
    logs = lire_logs('network_log.txt')
    stats = calculer_stats(logs)
    suspectes = detecter_suspectes(logs)
    
    print("\n=== STATISTIQUES ===")
    
    
    print("\n=== ACTIVITÉS SUSPECTES ===")
    
    
    generer_rapport(stats, suspectes, logs)
