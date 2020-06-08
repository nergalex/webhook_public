from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from Tower import SDK


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
        tower = {
            'hostname': '212.121.177.199',
            'username': 'webhook-nginx-unit',
            'password': 'webhook-nginx-unit',
            'client_id': 'Ric3P6v9MGxTMOivs9xNeBVFw4IhpKyteWqOEUAi',
            'client_secret': 'Lbw165xlH53vE03D8J2teJLqx30Xq5bPs3kysqbQSPDbOSlGkiJPlqMpZc3HOQ1FjF0YkcdMjiRu1z4BLzT9qmidJDHXQsFQ9BSJ2E2ymfWJlYxBFzzBLFXlt0Eix2sl'
        }
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

"""
# Start program
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:5000/apidocs/")
    application.run(
        host="0.0.0.0",
        use_reloader=True,
        port=5000
    )
"""

