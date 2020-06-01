from flask import (Flask, make_response, jsonify, request)
from flask_restful import (Api, Resource, reqparse, abort)
from flasgger import Swagger
from Tower import SDK
import argparse
import configparser
import pprint


# imported parameters in .ini file :
# section
ini_api_section             = "Listener"
# parameters in section
ini_api_bind_address        = "BindAddr"
ini_api_bind_port           = "BindPort"


# -------------- API --------------
# listener
webhook_listener = Flask(__name__)
api = Api(webhook_listener)
swagger = Swagger(webhook_listener)


def main():
    # Handling arguments
    """
    args                = get_args()
    debug               = args.debug
    verbose             = args.verbose
    log_file            = args.logfile
    ini_file            = args.inifile

    """
    # Bouchonnage arguments
    debug = True
    verbose = True
    log_file = 'logs/webhook.log'
    ini_file = 'webhook.ini'

    global tower, platform_name
    tower = {
        'hostname': '212.121.177.199',
        'username': 'pycharm',
        'password': 'PyCh4rm',
        'client_id': 'obgQYVVoOeGZ6PoVuoyeYXHyglrHFAx7ZHysp5F0',
        'client_secret': 'JnbyMNlgGlWX1zZ5A3OmHAUQ5e8UI2vdO15SqDCgj85eEHYM74jgad5BnQ6vVuHmVkFNEmb3MZNk8xEXeJNm1br5gvvbIQQRwlbpYnxrtgxkboRwgaIWR18GWntIdArW'
    }
    platform_name = 'TotalInbound'

    # Logging settings
    global logger
    logger = setup_logging(debug, verbose, log_file)

    # Load configuration
    global config
    config = configparser.RawConfigParser()
    config.read(ini_file)

    # Get parameters from config (.ini file)
    global param
    param = ConfigParameter()

    # Step 4. Start API
    logger.warning("webhook started")
    pprint.pprint("API dev portal: http://127.0.0.1:8000/apidocs/")
    webhook_listener.run(
        debug=debug,
        host=param.api_bind_address,
        port=param.api_bind_port,
        use_reloader=True
    )


def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description="Run webhook.")
    parser.add_argument('-d', '--debug',
                        required=False,
                        help='Enable debug output',
                        dest='debug',
                        action='store_true')
    parser.add_argument('-v', '--verbose',
                        required=False,
                        help='Enable verbose output',
                        dest='verbose',
                        action='store_true')
    parser.add_argument('-l', '--log-file',
                        required=False,
                        help='File to log to',
                        dest='logfile',
                        type=str,
                        default="webhook.log")
    parser.add_argument('-p', '--ini-file',
                        required=False,
                        help='File that contain parameters',
                        dest='inifile',
                        type=str,
                        default="webhook.ini")
    args = parser.parse_args()
    return args


def setup_logging(debug, verbose, log_file):
    import logging

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


def output_txt_response_format(data, code, headers=None):
    resp = make_response(data, code)
    resp.headers.extend(headers or {})
    return resp


class ConfigParameter(object):
    def __init__(self):
        # Initialize Defaults
        self.api_bind_address = '127.0.0.1'
        self.api_bind_port = '80'

        # Get attributes from .ini file
        self.parse_file()

    def parse_file(self):
        logger.info("INI file: get parameters")
        # API
        if config.has_section(ini_api_section):
            # BindAddr
            if config.has_option(ini_api_section, ini_api_bind_address):
                self.api_bind_address = config.get(ini_api_section, ini_api_bind_address)
            if config.has_option(ini_api_section, ini_api_bind_port):
                self.api_bind_port = config.get(ini_api_section, ini_api_bind_port)
        else:
            logger.error("No Listener Section")


@swagger.definition('vmss_context', tags=['v2_model'])
class VMSSContext(object):
    """
    Recommendation Query Context
    ---
    required:
      - id
      - resourceName
      - resourceRegion
    properties:
      resourceId:
        type: string
        description: VMSS ID
      resourceName:
        type: string
        description: VMSS name
      resourceRegion:
        type: string
        description: VMSS location
    """


class ApiAutoScale(Resource):
    def get(self, vmss_name):
        """
        Get monitor status
        ---
        tags:
          - vmss
        parameters:
          - in: path
            name: vmss_name
            required: true
            description: VMSS name
            type: string
        responses:
          200:
            description: The task data
        """
        msg = "Monitor test " + vmss_name + " OK"
        return msg, 201

    def post(self, vmss_name):
        """
        Launch a new VM Scale Set synchronization
        ---
        tags:
          - vmss
        consumes:
          - application/json; charset=utf-8
        parameters:
          - in: body
            name: body
            schema:
              required:
                - operation
                - context
              properties:
                operation:
                  type: string
                  description: VM Scale Set Operation
                  default: 'Scale Out'
                  enum: ['Scale In', 'Scale Out']
                context:
                  type: object
                  schema:
                  $ref: '#/definitions/vmss_context'
        responses:
          200:
            description: A job has been launched on Ansible Tower
         """
        data_json = request.get_json(force=True)
        logger.info("api=ApiAutoScale;method=POST;vmss=%s;operation=%s;id=%s;resourceRegion=%s" %
                    (data_json['context']['resourceName'], data_json['operation'], data_json['context']['id'], data_json['context']['resourceRegion']))

        orchestrator = SDK.TowerApi(
            host=tower['hostname'],
            username=tower['username'],
            password=tower['password'],
            client_id=tower['client_id'],
            client_secret=tower['client_secret'],
            port=443,
        )
        orchestrator.get_token()

        if vmss_name.startswith('nginx'):
            if data_json['operation'].lower() == 'scale out':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-autoscale-nginx-scale-out',
                    extra_vars={
                        'extra_location': data_json['context']['resourceRegion'],
                        'extra_vmss_name': data_json['context']['resourceName'],
                        'extra_vmss_id': data_json['context']['resourceId'],
                        'extra_platform_name': platform_name,
                    }
                )

        return "Job launched", 201


api.add_resource(ApiAutoScale, '/autoscale/<vmss_name>')

# Start program
if __name__ == "__main__":
    main()
