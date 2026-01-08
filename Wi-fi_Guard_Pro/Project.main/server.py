from flask import Flask, jsonify, render_template
from flask_cors import CORS
import speedtest

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index1.html')

@app.route('/speedtest')
def speed_test():
    st = speedtest.Speedtest()
    st.get_best_server()
    download_speed = st.download() / 1_000_000  
    upload_speed = st.upload() / 1_000_000      
    ping = st.results.ping

    return jsonify({
        'download': round(download_speed, 2),
        'upload': round(upload_speed, 2),
        'latency': round(ping, 2)
    })

if __name__ == '__main__':
    app.run(debug=True)
