
import subprocess

'''
ping con intervallo di 5 secondi per 5 volte
registra:
    - min tempo di risposta
    - max tempo di risposta
    - tempo medio di risposta
'''

ping = subprocess.run(['ping', '-i 5', '-c 5', 'google.com'], stdout=subprocess.PIPE).stdout.decode('utf8').split('\n')

min, avg, max = ping[-2].split('=')[-1].split('/')[:3]

stat = dict({
    'min': min.strip(),
    'avg': avg.strip(),
    'max': max.strip(),
})

print(stat)