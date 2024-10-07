from flask import Flask, render_template, jsonify, request
import nmap
import json

app = Flask(__name__)

def scan_network(ip_range):
    nm = nmap.PortScanner()
    print(f"네트워크 스캔 중: {ip_range}")
    nm.scan(hosts=ip_range, arguments='-p 80 --open')
    
    cctv_devices = []
    for host in nm.all_hosts():
        if '80/tcp' in nm[host]['tcp']:
            device_info = {
                'ip': host,
                'state': nm[host]['tcp'][80]['state'],
                'uid': f"CCTV-{host.replace('.', '')}"
            }
            cctv_devices.append(device_info)
    
    return cctv_devices

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_range = request.json.get('ip_range', '0.0.0.0/0')  # 기본적으로 전체 네트워크를 스캔
    devices = scan_network(ip_range)
    return jsonify(devices)

@app.route('/save', methods=['POST'])
def save_results():
    data = request.json
    with open('scan_results.json', 'w') as file:
        json.dump(data, file)
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True)
