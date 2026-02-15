#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256
#define THRESHOLD_SUSPECT 5

typedef struct {
    char date[11];
    char heure[9];
    char ip_source[16];
    int port;
    char protocole[4];
    char statut[7];
} LogEntry;

LogEntry* lire_logs(const char* nom_fichier, int* nb_logs) {
    FILE* fichier;
    LogEntry* logs;
    char ligne[MAX_LINE_LENGTH];
    char* token;
    int i;

    fichier = fopen(nom_fichier, "r");
    if (!fichier) {
        printf("Erreur : impossible d'ouvrir le fichier %s\n", nom_fichier);
        *nb_logs = 0;
        return NULL;
    }

    logs = NULL;
    *nb_logs = 0;

    while (fgets(ligne, sizeof(ligne), fichier)) {
        ligne[strcspn(ligne, "\n")] = 0;
        logs = realloc(logs, (*nb_logs + 1) * sizeof(LogEntry));

        token = strtok(ligne, ";");
        strcpy(logs[*nb_logs].date, token);

        token = strtok(NULL, ";");
        strcpy(logs[*nb_logs].heure, token);

        token = strtok(NULL, ";");
        strcpy(logs[*nb_logs].ip_source, token);

        token = strtok(NULL, ";");
        logs[*nb_logs].port = atoi(token);

        token = strtok(NULL, ";");
        strcpy(logs[*nb_logs].protocole, token);

        token = strtok(NULL, ";");
        strcpy(logs[*nb_logs].statut, token);

        (*nb_logs)++;
    }

    fclose(fichier);
    return logs;
}

void statistiques_generales(LogEntry* logs, int nb_logs,
                           int* total, int* succes, int* echec) {
    int i;
    *total = nb_logs;
    *succes = 0;
    *echec = 0;

    for (i = 0; i < nb_logs; i++) {
        if (strcmp(logs[i].statut, "SUCCES") == 0) {
            (*succes)++;
        } else {
            (*echec)++;
        }
    }
}

int trouver_port_plus_utilise(LogEntry* logs, int nb_logs) {
    typedef struct {
        int port;
        int count;
    } PortCount;

    PortCount* ports;
    int nb_ports;
    int i, j;
    int trouve;
    int port_max, count_max;

    ports = NULL;
    nb_ports = 0;

    for (i = 0; i < nb_logs; i++) {
        trouve = 0;
        for (j = 0; j < nb_ports; j++) {
            if (ports[j].port == logs[i].port) {
                ports[j].count++;
                trouve = 1;
                break;
            }
        }
        if (!trouve) {
            ports = realloc(ports, (nb_ports + 1) * sizeof(PortCount));
            ports[nb_ports].port = logs[i].port;
            ports[nb_ports].count = 1;
            nb_ports++;
        }
    }

    port_max = 0;
    count_max = 0;
    for (i = 0; i < nb_ports; i++) {
        if (ports[i].count > count_max) {
            count_max = ports[i].count;
            port_max = ports[i].port;
        }
    }

    free(ports);
    return port_max;
}

void trouver_ip_plus_active(LogEntry* logs, int nb_logs, char* ip_plus_active) {
    typedef struct {
        char ip[16];
        int count;
    } IPCount;

    IPCount* ips;
    int nb_ips;
    int i, j;
    int trouve;
    int count_max;

    ips = NULL;
    nb_ips = 0;

    for (i = 0; i < nb_logs; i++) {
        trouve = 0;
        for (j = 0; j < nb_ips; j++) {
            if (strcmp(ips[j].ip, logs[i].ip_source) == 0) {
                ips[j].count++;
                trouve = 1;
                break;
            }
        }
        if (!trouve) {
            ips = realloc(ips, (nb_ips + 1) * sizeof(IPCount));
            strcpy(ips[nb_ips].ip, logs[i].ip_source);
            ips[nb_ips].count = 1;
            nb_ips++;
        }
    }

    count_max = 0;
    strcpy(ip_plus_active, "");
    for (i = 0; i < nb_ips; i++) {
        if (ips[i].count > count_max) {
            count_max = ips[i].count;
            strcpy(ip_plus_active, ips[i].ip);
        }
    }

    free(ips);
}

void detecter_ip_suspectes(LogEntry* logs, int nb_logs) {
    typedef struct {
        char ip[16];
        int port;
        int echecs;
    } SuspectEntry;

    SuspectEntry* suspects;
    int nb_suspects;
    int i, j;
    int trouve;
    int trouve_suspect;

    printf("\n=== IP SUSPECTES ===\n");
    printf("IP suspectes (> %d echecs sur un meme port) :\n", THRESHOLD_SUSPECT);

    suspects = NULL;
    nb_suspects = 0;

    for (i = 0; i < nb_logs; i++) {
        if (strcmp(logs[i].statut, "ECHEC") == 0) {
            trouve = 0;
            for (j = 0; j < nb_suspects; j++) {
                if (strcmp(suspects[j].ip, logs[i].ip_source) == 0 &&
                    suspects[j].port == logs[i].port) {
                    suspects[j].echecs++;
                    trouve = 1;
                    break;
                }
            }
            if (!trouve) {
                suspects = realloc(suspects, (nb_suspects + 1) * sizeof(SuspectEntry));
                strcpy(suspects[nb_suspects].ip, logs[i].ip_source);
                suspects[nb_suspects].port = logs[i].port;
                suspects[nb_suspects].echecs = 1;
                nb_suspects++;
            }
        }
    }

    trouve_suspect = 0;
    for (i = 0; i < nb_suspects; i++) {
        if (suspects[i].echecs > THRESHOLD_SUSPECT) {
            printf("- %s (port %d) : %d echecs\n",
                   suspects[i].ip, suspects[i].port, suspects[i].echecs);
            trouve_suspect = 1;
        }
    }

    if (!trouve_suspect) {
        printf("Aucune IP suspecte detectee.\n");
    }

    free(suspects);
}

void top_3_ports(LogEntry* logs, int nb_logs, int top_ports[3]) {
    typedef struct {
        int port;
        int count;
    } PortCount;

    PortCount* ports;
    int nb_ports;
    int i, j, k;
    int trouve;
    PortCount temp;

    ports = NULL;
    nb_ports = 0;

    for (i = 0; i < nb_logs; i++) {
        trouve = 0;
        for (j = 0; j < nb_ports; j++) {
            if (ports[j].port == logs[i].port) {
                ports[j].count++;
                trouve = 1;
                break;
            }
        }
        if (!trouve) {
            ports = realloc(ports, (nb_ports + 1) * sizeof(PortCount));
            ports[nb_ports].port = logs[i].port;
            ports[nb_ports].count = 1;
            nb_ports++;
        }
    }

    for (i = 0; i < nb_ports - 1; i++) {
        for (j = i + 1; j < nb_ports; j++) {
            if (ports[i].count < ports[j].count) {
                temp = ports[i];
                ports[i] = ports[j];
                ports[j] = temp;
            }
        }
    }

    for (i = 0; i < 3; i++) {
        if (i < nb_ports) {
            top_ports[i] = ports[i].port;
        } else {
            top_ports[i] = 0;
        }
    }

    free(ports);
}

void generer_rapport(const char* nom_fichier, LogEntry* logs, int nb_logs) {
    FILE* rapport;
    int total, succes, echec;
    int port_plus_utilise;
    char ip_plus_active[16];
    int top_ports[3];

    typedef struct {
        char ip[16];
        int port;
        int echecs;
    } SuspectEntry;

    SuspectEntry* suspects;
    int nb_suspects;
    int nb_suspects_affiches;
    int i, j;
    int trouve;

    rapport = fopen(nom_fichier, "w");
    if (!rapport) {
        printf("Erreur : impossible de creer le fichier rapport\n");
        return;
    }

    statistiques_generales(logs, nb_logs, &total, &succes, &echec);
    port_plus_utilise = trouver_port_plus_utilise(logs, nb_logs);
    trouver_ip_plus_active(logs, nb_logs, ip_plus_active);
    top_3_ports(logs, nb_logs, top_ports);

    fprintf(rapport, "========================================\n");
    fprintf(rapport, "   RAPPORT D'ANALYSE DES LOGS RESEAU   \n");
    fprintf(rapport, "========================================\n\n");

    fprintf(rapport, "Date de l'analyse : %s\n\n", logs[0].date);

    fprintf(rapport, "--- STATISTIQUES GENERALES ---\n");
    fprintf(rapport, "Nombre total de connexions : %d\n", total);
    fprintf(rapport, "Connexions reussies : %d\n", succes);
    fprintf(rapport, "Connexions en echec : %d\n\n", echec);

    fprintf(rapport, "--- INDICATEURS CLES ---\n");
    fprintf(rapport, "Port le plus utilise : %d\n", port_plus_utilise);
    fprintf(rapport, "IP la plus active : %s\n\n", ip_plus_active);

    fprintf(rapport, "--- TOP 3 DES PORTS LES PLUS UTILISES ---\n");
    for (i = 0; i < 3; i++) {
        if (top_ports[i] != 0) {
            fprintf(rapport, "%d. Port %d\n", i + 1, top_ports[i]);
        }
    }
    fprintf(rapport, "\n");

    fprintf(rapport, "--- IP SUSPECTES DETECTEES ---\n");

    suspects = NULL;
    nb_suspects = 0;

    for (i = 0; i < nb_logs; i++) {
        if (strcmp(logs[i].statut, "ECHEC") == 0) {
            trouve = 0;
            for (j = 0; j < nb_suspects; j++) {
                if (strcmp(suspects[j].ip, logs[i].ip_source) == 0 &&
                    suspects[j].port == logs[i].port) {
                    suspects[j].echecs++;
                    trouve = 1;
                    break;
                }
            }
            if (!trouve) {
                suspects = realloc(suspects, (nb_suspects + 1) * sizeof(SuspectEntry));
                strcpy(suspects[nb_suspects].ip, logs[i].ip_source);
                suspects[nb_suspects].port = logs[i].port;
                suspects[nb_suspects].echecs = 1;
                nb_suspects++;
            }
        }
    }

    nb_suspects_affiches = 0;
    for (i = 0; i < nb_suspects; i++) {
        if (suspects[i].echecs > THRESHOLD_SUSPECT) {
            fprintf(rapport, "- %s (port %d) : %d echecs\n",
                    suspects[i].ip, suspects[i].port, suspects[i].echecs);
            nb_suspects_affiches++;
        }
    }

    if (nb_suspects_affiches == 0) {
        fprintf(rapport, "Aucune IP suspecte detectee.\n");
    }

    fprintf(rapport, "\n========================================\n");
    fprintf(rapport, "Fin du rapport - Analyse terminee\n");
    fprintf(rapport, "========================================\n");

    free(suspects);
    fclose(rapport);

    printf("Rapport genere avec succes : %s\n", nom_fichier);
}

int main() {
    int nb_logs;
    LogEntry* logs;
    int total, succes, echec;
    int port_plus_utilise;
    char ip_plus_active[16];
    int top_ports[3];
    int i;

    printf("=== ANALYSEUR DE LOGS RESEAU ===\n\n");

    logs = lire_logs("network_log.txt", &nb_logs);

    if (!logs) {
        return 1;
    }

    printf("Fichier lu avec succes : %d entrees de log\n\n", nb_logs);

    statistiques_generales(logs, nb_logs, &total, &succes, &echec);

    printf("--- STATISTIQUES GENERALES ---\n");
    printf("Nombre total de connexions : %d\n", total);
    printf("Connexions reussies : %d\n", succes);
    printf("Connexions en echec : %d\n\n", echec);

    port_plus_utilise = trouver_port_plus_utilise(logs, nb_logs);
    printf("Port le plus utilise : %d\n\n", port_plus_utilise);

    trouver_ip_plus_active(logs, nb_logs, ip_plus_active);
    printf("IP la plus active : %s\n\n", ip_plus_active);

    detecter_ip_suspectes(logs, nb_logs);

    top_3_ports(logs, nb_logs, top_ports);
    printf("\n--- TOP 3 DES PORTS LES PLUS UTILISES ---\n");
    for (i = 0; i < 3; i++) {
        if (top_ports[i] != 0) {
            printf("%d. Port %d\n", i + 1, top_ports[i]);
        }
    }

    printf("\n");
    generer_rapport("rapport_analyse.txt", logs, nb_logs);

    free(logs);

    printf("\nAnalyse terminee.\n");
    return 0;
}
