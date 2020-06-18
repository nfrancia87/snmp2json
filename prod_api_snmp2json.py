from flask import Flask, request, jsonify
from prod_snmp2json_v2 import SnmpObject

app = Flask(__name__)
@app.route('/ping', methods=['GET'])
def ping():
	return jsonify({'response': 'pong!'})

@app.route('/api/v1/device/<string:device_name>/community/<string:community>',methods=['GET'])
def getData(device_name,community):
	Object = SnmpObject(community,device_name)
	response = jsonify(Object.get_snmp_data())
	return response

@app.route('/api/v1/device/<string:device_name>/community/<string:community>/basicData',methods=['GET'])
def get_basic_data(device_name,community):
	Object = SnmpObject(community,device_name)
	response = jsonify(Object.getBasicSnmpData())
	try:
		if ("Timeout from host "+ device_name) in response:
			return response
		elif ("Unknown host ") in response:
			return response
	except TypeError:
		return response

@app.errorhandler(404)
def not_found(error=None):
	message = {
		'message': 'Resource Not Found ' + request.url,
		'status': 404
	}
	response = jsonify(message)
	response.status_code = 404
	return response
if __name__ == '__main__':
	app.run(debug=True,host='0.0.0.0', ssl_context='adhoc', port=5005)
