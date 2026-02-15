# TP - Analyse de logs réseau

Dépôt contenant deux implémentations du programme d'analyse de logs réseau demandé dans le TP :

- Version C : `version-c/analyse_logs.c`
- Version Python : `version-python/analyse_logs.py`

## Compilation – Version C

bash
cd version-c
gcc -Wall -o analyse_logs analyse_logs.c
./analyse_logs ../network_log.txt

## Compilation - version python 

bash 
cd version-python
python analyse_logs.py ../network_log.txt
# ou avec python3 si nécessaire :
python3 analyse_logs.py ../network_log.txt