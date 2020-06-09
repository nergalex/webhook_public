from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from Tower import SDK
import configparser
import logging

# imported parameters in .ini file :
ini_file = 'webhook.ini'
ini_tower_section           = "tower"
ini_tower_hostname            = "hostname"
ini_tower_username            = "username"
ini_tower_password            = "password"
ini_tower_client_id           = "client_id"
ini_tower_client_secret       = "client_secret"
ini_log_section           = "log"
ini_log_state       = "state"
ini_log_file       = "file"
ini_log_level       = "level"


def setup_logging(log_file, log_level):
    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level in ('verbose', 'info'):
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


class ConfigParameter(object):
    def __init__(self):
        self.tower_hostname = ''
        self.tower_username = ''
        self.tower_password = ''
        self.tower_client_id = ''
        self.tower_client_secret = ''
        self.log_state = 'off'
        self.log_file = '/var/logs/webhook/webhook.log'
        self.log_level = 'info'
        self.parse_file()

    def parse_file(self):
        if config.has_section(ini_tower_section):
            if config.has_option(ini_tower_section, ini_tower_hostname):
                self.tower_hostname = config.get(ini_tower_section, ini_tower_hostname)
            if config.has_option(ini_tower_section, ini_tower_username):
                self.tower_username = config.get(ini_tower_section, ini_tower_username)
            if config.has_option(ini_tower_section, ini_tower_password):
                self.tower_password = config.get(ini_tower_section, ini_tower_password)
            if config.has_option(ini_tower_section, ini_tower_client_id):
                self.tower_client_id = config.get(ini_tower_section, ini_tower_client_id)
            if config.has_option(ini_tower_section, ini_tower_client_secret):
                self.tower_client_secret = config.get(ini_tower_section, ini_tower_client_secret)
        else:
            raise ValueError('No Tower Section in .ini file')

        if config.has_section(ini_log_section):
            if config.has_option(ini_log_section, ini_log_state):
                self.log_state = config.get(ini_log_section, ini_log_state)
            if config.has_option(ini_log_section, ini_log_file):
                self.log_file = config.get(ini_log_section, ini_log_file)
            if config.has_option(ini_log_section, ini_log_level):
                self.log_level = config.get(ini_log_section, ini_log_level)


# Load global configuration
global param
config = configparser.RawConfigParser()
config.read(ini_file)
param = ConfigParameter()
global logger
logger = setup_logging(param.log_file, param.log_level)
global tower
tower = {
    'hostname': param.tower_hostname,
    'username': param.tower_username,
    'password': param.tower_password,
    'client_id': param.tower_client_id,
    'client_secret': param.tower_client_secret
}


# -------------- API --------------
# listener
logger.warning("webhook started")
application = Flask(__name__)
"""
application.config['SWAGGER'] = {
    'title': 'webhook autoscale F5',
    'openapi': '3.0.2'
}
"""
api = Api(application)
swagger = Swagger(application)


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
        logger.debug(msg)
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
        extra_vars = {
            'extra_location': data_json['context']['resourceRegion'],
            'extra_vmss_name': data_json['context']['resourceName'],
        }

        if vmss_name.startswith('nginxwaf'):
            if data_json['operation'].lower() == 'scale out':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_out_nginx_app_protect',
                    extra_vars=extra_vars
                )
            elif data_json['operation'].lower() == 'scale in':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_in_nginx',
                    extra_vars=extra_vars
                )
            else:
                error_msg = "unknown operation:" + data_json['operation']
                return error_msg, 403
        elif vmss_name.startswith('nginxapigw'):
            if data_json['operation'].lower() == 'scale out':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_out_nginx_second_line',
                    extra_vars=extra_vars
                )
            elif data_json['operation'].lower() == 'scale in':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_in_nginx',
                    extra_vars=extra_vars
                )
            else:
                error_msg = "unknown operation:" + data_json['operation']
                return error_msg, 403
        elif vmss_name.startswith('awaf'):
            if data_json['operation'].lower() == 'scale out':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_out_bigip',
                    extra_vars=extra_vars
                )
            elif data_json['operation'].lower() == 'scale in':
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_in_bigip',
                    extra_vars=extra_vars
                )
            else:
                error_msg = "unknown operation:" + data_json['operation']
                return error_msg, 403
        elif vmss_name.startswith('test'):
            orchestrator.workflow_job_templates__id_launch(
                name='wf-autoscale_webhook_test',
                extra_vars=extra_vars
            )
        else:
            error_msg = "unknown vmss_name:" + vmss_name
            return error_msg, 403
        return "Workflow Job launched", 201


api.add_resource(ApiAutoScale, '/autoscale/<vmss_name>')

# Start program
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:5000/apidocs/")
    application.run(
        host="0.0.0.0",
        use_reloader=True,
        port=5000
    )

