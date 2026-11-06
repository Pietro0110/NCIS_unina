"""
Topologia Mininet per il progetto: "Traffic Monitoring in SDN".
Corso: Network and Cloud Infrastructures (UniNa)

Topologia a stella:
- 1 Switch OpenFlow 1.3 (s1)
- 3 Host (h1, h2, h3)
- Connessione a controller remoto (Ryu) in esecuzione su 127.0.0.1:6653
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def create_topology():
    """Crea la topologia di rete, avvia Mininet e apre la CLI interattiva."""
    info('*** Inizializzazione della rete Mininet\n')
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    info('*** Configurazione Controller remoto (Ryu su 127.0.0.1:6653)\n')
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    info('*** Creazione Switch OpenFlow 1.3 (s1)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info('*** Creazione Host (h1, h2, h3)\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

    info('*** Collegamento dei link fisici (Star Topology)\n')
    # Port 1 sullo switch s1 -> h1
    net.addLink(h1, s1)
    # Port 2 sullo switch s1 -> h2
    net.addLink(h2, s1)
    # Port 3 sullo switch s1 -> h3
    net.addLink(h3, s1)

    info('*** Avvio della rete\n')
    net.start()

    info('\n=======================================================\n')
    info(' Topologia avviata con successo!\n')
    info(' Esempi di comandi da eseguire nella CLI di Mininet:\n')
    info('   mininet> pingall\n')
    info('   mininet> h1 ping -c 10 h2\n')
    info('   mininet> iperf h1 h2\n')
    info(' Per uscire digita "exit" o premi Ctrl+D\n')
    info('=======================================================\n\n')

    # Apertura della CLI per test interattivi
    CLI(net)

    info('*** Arresto e pulizia della rete Mininet\n')
    net.stop()


if __name__ == '__main__':
    # Imposta livello di log informativo
    setLogLevel('info')
    create_topology()
