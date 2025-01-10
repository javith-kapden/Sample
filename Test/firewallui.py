from flask import Flask
import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
import subprocess
import re

class FirewallTool:
    def __init__(self):
        self.rules = []

    def add_rule(self, protocol, src_ip, src_port, dst_ip, dst_port, action):
        rule = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'action': action
        }
        self.rules.append(rule)

    def remove_rule(self, protocol, src_ip, src_port, dst_ip, dst_port):
        for rule in self.rules:
            if (rule['protocol'] == protocol and
                rule['src_ip'] == src_ip and
                rule['src_port'] == src_port and
                rule['dst_ip'] == dst_ip and
                rule['dst_port'] == dst_port):
                self.rules.remove(rule)
                return True
        return False

    def list_rules(self):
        if not self.rules:
            return "No rules configured."
        return '\n'.join([
            f"Protocol: {rule['protocol']}, Src IP: {rule['src_ip']}, Src Port: {rule['src_port']}, Dst IP: {rule['dst_ip']}, Dst Port: {rule['dst_port']}, Action: {rule['action']}"
            for rule in self.rules
        ])

    def apply_rules(self):
        self.flush_rules()  # Ensure previous rules are flushed
        for rule in self.rules:
            if rule['action'] == 'allow':
                self._add_allow_rule(rule)
            elif rule['action'] == 'block':
                self._add_block_rule(rule)

    def _add_allow_rule(self, rule):
        command = f"iptables -A INPUT -p {rule['protocol']} -s {rule['src_ip']} --sport {rule['src_port']} -d {rule['dst_ip']} --dport {rule['dst_port']} -j ACCEPT"
        subprocess.run(command, shell=True, check=True)

    def _add_block_rule(self, rule):
        command = f"iptables -A INPUT -p {rule['protocol']} -s {rule['src_ip']} --sport {rule['src_port']} -d {rule['dst_ip']} --dport {rule['dst_port']} -j DROP"
        subprocess.run(command, shell=True, check=True)

    def flush_rules(self):
        subprocess.run("iptables -F", shell=True, check=True)

app = Flask(__name__)
dash_app = dash.Dash(__name__, server=app, suppress_callback_exceptions=True)

firewall = FirewallTool()

dash_app.layout = html.Div(className='container', children=[
    html.H1('Advanced Firewall Tool'),
    html.P('Configure your firewall settings:'),
    dcc.Dropdown(
        id='protocol-dropdown',
        options=[
            {'label': 'TCP', 'value': 'tcp'},
            {'label': 'UDP', 'value': 'udp'},
            {'label': 'ICMP', 'value': 'icmp'}
        ],
        value='tcp',
        className='dropdown'
    ),
    dcc.Input(id='src-ip-input', type='text', placeholder='Source IP', className='input'),
    dcc.Input(id='src-port-input', type='number', placeholder='Source Port', className='input'),
    dcc.Input(id='dst-ip-input', type='text', placeholder='Destination IP', className='input'),
    dcc.Input(id='dst-port-input', type='number', placeholder='Destination Port', className='input'),
    dcc.Dropdown(
        id='action-dropdown',
        options=[
            {'label': 'Allow', 'value': 'allow'},
            {'label': 'Block', 'value': 'block'}
        ],
        value='allow',
        className='dropdown'
    ),
    html.Button('Add Rule', id='add-button', n_clicks=0, className='button'),
    html.Button('Remove Rule', id='remove-button', n_clicks=0, className='button'),
    html.Button('List Rules', id='list-button', n_clicks=0, className='button'),
    html.Button('Apply Rules', id='apply-button', n_clicks=0, className='button'),
    html.Button('Flush Rules', id='flush-button', n_clicks=0, className='button'),
    html.Div(id='output-container', className='output'),
    html.Script(src='/assets/script.js'),
])

@dash_app.callback(
    Output('output-container', 'children'),
    [Input('add-button', 'n_clicks'),
     Input('remove-button', 'n_clicks'),
     Input('list-button', 'n_clicks'),
     Input('apply-button', 'n_clicks'),
     Input('flush-button', 'n_clicks')],
    [State('protocol-dropdown', 'value'),
     State('src-ip-input', 'value'),
     State('src-port-input', 'value'),
     State('dst-ip-input', 'value'),
     State('dst-port-input', 'value'),
     State('action-dropdown', 'value')]
)
def handle_callbacks(n_clicks_add, n_clicks_remove, n_clicks_list, n_clicks_apply, n_clicks_flush, protocol, src_ip, src_port, dst_ip, dst_port, action):
    # Validate inputs
    if not all([protocol, src_ip, dst_ip, src_port, dst_port, action]):
        return "Please fill out all fields."

    # Validate IP addresses
    if not (re.match(r'^\d{1,3}(\.\d{1,3}){3}$', src_ip) and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', dst_ip)):
        return "Invalid IP address format."

    # Validate port numbers
    if not (0 <= int(src_port) <= 65535 and 0 <= int(dst_port) <= 65535):
        return "Port numbers must be between 0 and 65535."

    if n_clicks_add > 0:
        firewall.add_rule(protocol, src_ip, src_port, dst_ip, dst_port, action)
        return f"Added rule: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {action}"
    elif n_clicks_remove > 0:
        if firewall.remove_rule(protocol, src_ip, src_port, dst_ip, dst_port):
            return f"Removed rule: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        else:
            return f"No rule found: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    elif n_clicks_list > 0:
        return firewall.list_rules()
    elif n_clicks_apply > 0:
        firewall.apply_rules()
        return "Applied rules"
    elif n_clicks_flush > 0:
        firewall.flush_rules()
        return "Flushed rules"
    else:
        return ""

if __name__ == '__main__':
    app.run(debug=True)
