from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from Tower import SDK
import configparser

# imported parameters in .ini file :
ini_file = 'webhook.ini'
ini_tower_section           = "tower"
ini_tower_hostname            = "hostname"
ini_tower_username            = "username"
ini_tower_password            = "password"
ini_tower_client_id           = "client_id"
ini_tower_client_secret       = "client_secret"


class ConfigParameter(object):
    def __init__(self):
        self.tower_hostname = ''
        self.tower_username = ''
        self.tower_password = ''
        self.tower_client_id = ''
        self.tower_client_secret = ''
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


# Load global configuration
config = configparser.RawConfigParser()
config.read(ini_file)
param = ConfigParameter()
tower = {
    'hostname': param.tower_hostname,
    'username': param.tower_username,
    'password': param.tower_password,
    'client_id': param.tower_client_id,
    'client_secret': param.tower_client_secret
}


# -------------- API --------------
# listener
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
        default: test
        description: VMSS name
        enum: ['awaf', 'nginxapigw', 'nginxwaf', 'test']
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
            description: Returns a URL link
            schema:
              id: Users
              type: object
              properties:
                users:
                  type: array
                  items:
                    $ref: '#/definitions/User'
            examples:
              users: [{'name': 'Russel Allen', 'team': 66}]
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
            extra_vars['extra_env_prefix'] = "env_north_"
            if data_json['operation'].lower() == 'scale out':
                # wf-scale_out_nginx_app_protect_from_nginx_repo
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_out_nginx_controller_north',
                    extra_vars=extra_vars
                )
            elif data_json['operation'].lower() == 'scale in':
                # wf-scale_in_nginx_controller
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_in_nginx_controller',
                    extra_vars=extra_vars
                )
            else:
                error_msg = "unknown operation:" + data_json['operation']
                return error_msg, 403
        elif vmss_name.startswith('nginxapigw'):
            extra_vars['extra_env_prefix'] = "env_south_"
            if data_json['operation'].lower() == 'scale out':
                # wf-scale_out_nginx_second_line
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_out_nginx_controller_south',
                    extra_vars=extra_vars
                )
            elif data_json['operation'].lower() == 'scale in':
                # wf-scale_in_nginx_controller
                orchestrator.workflow_job_templates__id_launch(
                    name='wf-scale_in_nginx_controller',
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

