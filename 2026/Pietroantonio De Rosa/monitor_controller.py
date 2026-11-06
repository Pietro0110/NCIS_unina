"""
Ryu SDN Controller con Traffic Monitoring in tempo reale (OpenFlow 1.3).
Corso: Network and Cloud Infrastructures (UniNa)

Caratteristiche:
- Switch L2 learning (inoltro basato su MAC address)
- Monitoraggio periodico ogni 5 secondi tramite hub.spawn
- Richieste statistiche: OFPPortStatsRequest e OFPFlowStatsRequest
- Gestione risposte: EventOFPPortStatsReply e EventOFPFlowStatsReply
- Calcolo del Throughput istantaneo (bps / Kbps / Mbps) e contatori pacchetti/byte
- Output formattato a tabella per report chiari ed esaustivi
"""

import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub


def format_rate(bps):
    """
    Formatta il throughput in bit al secondo in unità leggibili
    (bps, Kbps, Mbps, Gbps).
    """
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    else:
        return f"{bps:.2f} bps"


def format_bytes(num_bytes):
    """
    Formatta il volume di byte in unità leggibili (B, KB, MB, GB).
    """
    if num_bytes >= 1024**3:
        return f"{num_bytes / (1024**3):.2f} GB"
    elif num_bytes >= 1024**2:
        return f"{num_bytes / (1024**2):.2f} MB"
    elif num_bytes >= 1024:
        return f"{num_bytes / 1024:.2f} KB"
    else:
        return f"{num_bytes} B"


class TrafficMonitorController(app_manager.RyuApp):
    """
    Applicazione Ryu per lo switch L2 learning e monitoraggio periodico del traffico di rete.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficMonitorController, self).__init__(*args, **kwargs)

        # Tabella MAC learning: dpid -> {mac_address: port_no}
        self.mac_to_port = {}

        # Mappa dei datapath attivi: dpid -> datapath_object
        self.datapaths = {}

        # Dati storici per calcolo delta del throughput
        # (dpid, port_no) -> {'time': float, 'rx_bytes': int, 'tx_bytes': int, 'rx_packets': int, 'tx_packets': int}
        self.prev_port_stats = {}

        # flow_key -> {'time': float, 'byte_count': int, 'packet_count': int}
        self.prev_flow_stats = {}

        # Avvio del green thread per il monitoraggio periodico ogni 5 secondi
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("TrafficMonitorController avviato con successo. Intervallo di monitoraggio: 5s.")

    # =========================================================================
    # GESTIONE CONNESSIONE SWITCH & HANDSHAKE
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Registra o deregistra i datapath che si connettono o disconnettono."""
        datapath = ev.datapath
        dpid = datapath.id

        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.logger.info("Switch connesso al controller: DPID %016x", dpid)
                self.datapaths[dpid] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                self.logger.info("Switch disconnesso dal controller: DPID %016x", dpid)
                del self.datapaths[dpid]
                # Pulizia delle statistiche in cache per lo switch disconnesso
                self.prev_port_stats = {k: v for k, v in self.prev_port_stats.items() if k[0] != dpid}
                self.prev_flow_stats = {k: v for k, v in self.prev_flow_stats.items() if k[0] != dpid}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Fase di negoziazione delle feature (OFPSwitchFeatures).
        Installa la regola fondamentale di default (table-miss) con priorità 0:
        tutti i pacchetti non corrispondenti a regole note vengono inoltrati al controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match vuoto = qualsiasi pacchetto
        match = parser.OFPMatch()
        # Azione: invia al controller (OFPCML_NO_BUFFER evita buffer sullo switch)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Regola Table-Miss installata su DPID %016x", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        Helper method per installare una regola di flusso (FlowMod) sullo switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    # =========================================================================
    # L2 SWITCH LEARNING & FORWARDING
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestione dei pacchetti ricevuti dal controller (PacketIn).
        Implementa il meccanismo di apprendimento degli indirizzi MAC e installa flussi.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignora frame di tipo LLDP (discovery di topologia)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # Apprendimento del MAC sorgente e della relativa porta di ingresso
        self.mac_to_port[dpid][src] = in_port

        # Verifica della porta di destinazione
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Destinazione sconosciuta: esegue FLOOD su tutte le porte
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Se la destinazione è conosciuta, installa una regola di flusso nello switch
        # con un idle_timeout di 30 secondi (per consentire il monitoraggio dei flussi attivi)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=1, match=match, actions=actions,
                              buffer_id=msg.buffer_id, idle_timeout=30)
                return
            else:
                self.add_flow(datapath, priority=1, match=match, actions=actions,
                              idle_timeout=30)

        # Inoltro del pacchetto corrente verso la destinazione o in flooding
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # =========================================================================
    # MONITORAGGIO PERIODICO (POLLING A 5 SECONDI)
    # =========================================================================

    def _monitor(self):
        """
        Thread periodico di monitoraggio: invia richieste di statistiche
        ogni 5 secondi a tutti gli switch OpenFlow connessi.
        """
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        """
        Invia messaggi OFPPortStatsRequest e OFPFlowStatsRequest al datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 1. Richiesta statistiche flussi
        flow_req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(flow_req)

        # 2. Richiesta statistiche porte (OFPP_ANY per tutte le porte dello switch)
        port_req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(port_req)

    # =========================================================================
    # GESTIONE RISPOSTE STATISTICHE PORTE
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Gestisce la risposta dello switch con le statistiche delle porte fisiche/virtuali.
        Calcola pacchetti, byte totali e throughput RX/TX istantaneo per ogni porta.
        """
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        now = time.time()
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))

        # Filtra porte speciali (es. OFPP_LOCAL) e ordina numericamente per porta
        ports = [stat for stat in body if stat.port_no <= ofproto.OFPP_MAX]
        ports.sort(key=lambda s: s.port_no)

        if not ports:
            return

        print("\n" + "=" * 98, flush=True)
        print(f" [PORT MONITORING] - Switch DPID: {datapath.id:016x} | Rilevamento: {timestamp_str}", flush=True)
        print("=" * 98, flush=True)
        print(f"{'Porta':<7}{'RX Pkts':<12}{'TX Pkts':<12}{'RX Bytes':<14}{'TX Bytes':<14}{'RX Throughput':<19}{'TX Throughput':<19}", flush=True)
        print("-" * 98, flush=True)

        for stat in ports:
            port_key = (datapath.id, stat.port_no)
            prev = self.prev_port_stats.get(port_key)

            if prev:
                delta_t = now - prev['time']
                delta_rx_b = max(0, stat.rx_bytes - prev['rx_bytes'])
                delta_tx_b = max(0, stat.tx_bytes - prev['tx_bytes'])

                if delta_t > 0:
                    rx_rate_bps = (delta_rx_b * 8.0) / delta_t
                    tx_rate_bps = (delta_tx_b * 8.0) / delta_t
                else:
                    rx_rate_bps = 0.0
                    tx_rate_bps = 0.0
            else:
                rx_rate_bps = 0.0
                tx_rate_bps = 0.0

            # Salva lo stato corrente per il prossimo intervallo
            self.prev_port_stats[port_key] = {
                'time': now,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets
            }

            rx_bytes_str = format_bytes(stat.rx_bytes)
            tx_bytes_str = format_bytes(stat.tx_bytes)
            rx_rate_str = format_rate(rx_rate_bps)
            tx_rate_str = format_rate(tx_rate_bps)

            print(f"{stat.port_no:<7}{stat.rx_packets:<12}{stat.tx_packets:<12}{rx_bytes_str:<14}{tx_bytes_str:<14}{rx_rate_str:<19}{tx_rate_str:<19}", flush=True)

        print("-" * 98, flush=True)

    # =========================================================================
    # GESTIONE RISPOSTE STATISTICHE FLUSSI
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Gestisce la risposta con le statistiche della tabella di flusso (Flow Table).
        Visualizza le flow entries attive, pacchetti, byte e throughput associato.
        """
        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        now = time.time()
        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))

        # Ordinamento: priorità decrescente, poi conteggio pacchetti decrescente
        flows = sorted(body, key=lambda f: (f.priority, f.packet_count), reverse=True)

        print("\n" + "=" * 112, flush=True)
        print(f" [FLOW MONITORING] - Switch DPID: {datapath.id:016x} | Rilevamento: {timestamp_str}", flush=True)
        print("=" * 112, flush=True)
        print(f"{'Pri':<5}{'In-Port':<9}{'MAC Sorgente':<20}{'MAC Destinazione':<20}{'Azioni':<18}{'Pacchetti':<11}{'Byte':<13}{'Throughput':<15}", flush=True)
        print("-" * 112, flush=True)

        current_flow_keys = set()

        for stat in flows:
            # Ricostruzione leggibile delle azioni
            actions = []
            for instruction in stat.instructions:
                if hasattr(instruction, 'actions'):
                    for action in instruction.actions:
                        if hasattr(action, 'port'):
                            if action.port == ofproto.OFPP_CONTROLLER:
                                actions.append("CONTROLLER")
                            elif action.port == ofproto.OFPP_FLOOD:
                                actions.append("FLOOD")
                            else:
                                actions.append(f"OUT:{action.port}")
                        else:
                            actions.append(action.__class__.__name__)
            actions_str = ", ".join(actions) if actions else "DROP"

            # Estrazione campi di match (wildcard '*' se non specificati)
            match_dict = dict(stat.match.items()) if hasattr(stat.match, 'items') else {}
            in_port_val = str(match_dict.get('in_port', '*'))
            eth_src_val = str(match_dict.get('eth_src', '*'))
            eth_dst_val = str(match_dict.get('eth_dst', '*'))

            flow_key = (
                datapath.id,
                stat.priority,
                in_port_val,
                eth_src_val,
                eth_dst_val,
                actions_str
            )
            current_flow_keys.add(flow_key)

            prev = self.prev_flow_stats.get(flow_key)
            if prev:
                delta_t = now - prev['time']
                delta_b = max(0, stat.byte_count - prev['byte_count'])

                if delta_t > 0:
                    throughput_bps = (delta_b * 8.0) / delta_t
                else:
                    throughput_bps = 0.0
            else:
                throughput_bps = 0.0

            # Salva le statistiche correnti per il prossimo calcolo
            self.prev_flow_stats[flow_key] = {
                'time': now,
                'byte_count': stat.byte_count,
                'packet_count': stat.packet_count
            }

            bytes_str = format_bytes(stat.byte_count)
            rate_str = format_rate(throughput_bps)

            print(f"{stat.priority:<5}{in_port_val:<9}{eth_src_val:<20}{eth_dst_val:<20}{actions_str:<18}{stat.packet_count:<11}{bytes_str:<13}{rate_str:<15}", flush=True)

        print("-" * 112, flush=True)

        # Pulizia delle statistiche per flussi scaduti (rimossi dalla Flow Table)
        for old_key in list(self.prev_flow_stats.keys()):
            if old_key[0] == datapath.id and old_key not in current_flow_keys:
                del self.prev_flow_stats[old_key]
