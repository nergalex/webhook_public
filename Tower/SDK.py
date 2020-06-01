import json
import requests
import time
from requests.auth import HTTPBasicAuth


class TowerApi (object):
    def __init__(self, host, username, password, client_id, client_secret, port=443, logger=None):
        self.host = host
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.port = port
        self.logger = logger
        self.session = None
        self.access_token = None
        self.refresh_token = None

    def get_token(self):
        url = 'https://' + self.host + '/api/o/token/'

        # Create Token for an Application using Password grant type
        self.session = requests.session()
        headers = {
            'Referer': url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = 'grant_type=password&username=' + self.username + '&password=' + self.password + '&scope=write'
        r = self.session.post(
            url,
            headers=headers,
            data=data,
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
            verify=False)
        if self.logger:
            self.logger.info('Create Token for an Application using Password grant type from Tower server %s:%s with username %s' % (
                self.host, self.port, self.username))
        if r.status_code != requests.codes.ok:
            if self.logger:
                self.logger.error('%s::%s: code %s; %s' %
                                  (__class__.__name__, __name__, r.status_code, r.text))
            raise
        else:
            self.access_token = r.json()['access_token']
            self.refresh_token = r.json()['refresh_token']

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))

    def _get(self, path, parameters=None):
        """

        :param path: begins with '/' and ends with '/'
        :param parameters: array of parameters 'key=value'
        :return:
        """
        # URL builder
        if parameters and len(parameters) > 0:
            uri = path + '?' + '&'.join(parameters)
        else:
            uri = path

        url = 'https://' + self.host + uri
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.get(
            url,
            headers=headers,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        return r.json()

    def _post(self, path, data):
        url = 'https://' + self.host + path
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.post(
            url,
            headers=headers,
            json=data,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        if r.text == '':
            return {}
        else:
            return r.json()

    def _delete(self, path):
        url = 'https://' + self.host + path
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.delete(
            url,
            headers=headers,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        if r.text == '':
            return {}
        else:
            return r.json()

    def _patch(self, path, data):
        url = 'https://' + self.host + path
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.patch(
            url,
            headers=headers,
            json=data,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        return r.json()

    def organizations_get(self, name=None):
        path = '/api/v2/organizations/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def inventory_sources_get(self, name=None):
        path = '/api/v2/inventory_sources/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def inventory_sources__id__delete(self, name):
        # GET inventory_source
        inventory_source = self.inventory_sources_get(name=name)

        # UPDATE credential
        if len(inventory_source['results']) == 1:
            path = '/api/v2/inventory_sources/' + str(inventory_source['results'][0]['id']) + '/'
            return self._delete(path)

        # Unknown credential
        return None

    def inventories_get(self, name=None):
        path = '/api/v2/inventories/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def inventories_create(self, name, organization_name):
        # GET organization
        organization = self.organizations_get(name=organization_name)

        # GET inventory
        if len(organization['results']) == 1:
            inventory = self.inventories_get(name=name)

            # CREATE inventory
            if len(inventory['results']) == 0:
                url = '/api/v2/inventories/'
                data = {
                    'name': name,
                    'description': 'Created by CMP',
                    'organization': organization['results'][0]['id']
                }
                return self._post(url, data)

        # Unknown organization or existing inventory
        return None

    def inventories__id__delete(self, inventory_name):
        # GET inventory
        inventory = self.inventories_get(name=inventory_name)

        # DELETE inventory
        if len(inventory['results']) == 1:
            url = '/api/v2/inventories/' + str(inventory['results'][0]['id']) + '/'
            return self._delete(url)

        # Unknown inventory
        return None

    def inventories__id__hosts_get(self, inventory_name, host_name):
        # GET inventory
        inventory = self.inventories_get(name=inventory_name)

        # ADD localhost
        if len(inventory['results']) == 1:
            path = '/api/v2/inventories/' + str(inventory['results'][0]['id']) + '/hosts/'
            parameter = 'name=' + host_name
            parameters = [parameter]
            return self._get(path, parameters)

        # Unknown inventory
        return None

    def inventories__id__hosts_create(self, inventory_name, host_name):
        # GET inventory
        inventory = self.inventories_get(name=inventory_name)

        # GET host
        inventory = self.inventories__id__hosts_get(inventory_name=inventory_name, host_name=host_name)

        # ADD localhost
        if len(inventory['results']) == 1 and len(inventory['results']) == 0:
            url = '/api/v2/inventories/' + str(inventory['results'][0]['id']) + '/hosts/'
            data = {
                'name': host_name,
                'description': 'Created by CMP'
            }
            return self._post(url, data)

        # Unknown inventory or existing host
        return None

    def inventories__id__inventory_sources_create(self, inventory_name, inventory_source_name, credential_name,
                                                  source, source_regions, overwrite_vars=False, update_on_launch=False):
        # GET inventory
        inventory = self.inventories_get(name=inventory_name)

        # GET inventory source
        inventory_source = self.inventory_sources_get(name=inventory_source_name)

        # GET credential
        credential = self.credentials_get(name=credential_name)

        # CREATE inventory source
        if len(inventory['results']) == 1 and \
                len(credential['results']) == 1 and \
                len(inventory_source['results']) == 0:
            url = '/api/v2/inventories/' + str(inventory['results'][0]['id']) + '/inventory_sources/'
            data = {
                'name': inventory_source_name,
                'description': 'Created by CMP',
                'credential': credential['results'][0]['id'],
                'source': source,
                'source_regions': source_regions,
                'overwrite_vars': overwrite_vars,
                'update_on_launch': update_on_launch,
            }
            return self._post(url, data)

        # Unknown inventory or inventory source
        return None

    def credential_types_get(self, name=None):
        path = '/api/v2/credential_types/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def credentials_get(self, name=None):
        path = '/api/v2/credentials/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def credentials_create(self, name, credential_type_name, organization_name, inputs):
        # GET credential_type
        credential_type = self.credential_types_get(name=credential_type_name)

        # GET organization
        organization = self.organizations_get(name=organization_name)

        # GET credential
        if len(credential_type['results']) == 1 and len(organization['results']) == 1:
            credential = self.credentials_get(name=name)

            # CREATE credential
            if len(credential['results']) == 0:
                url = '/api/v2/credentials/'
                data = {
                    'name': name,
                    'description': 'Created by CMP',
                    'organization': organization['results'][0]['id'],
                    'credential_type': credential_type['results'][0]['id'],
                    'inputs': inputs
                }
                return self._post(url, data)

        # Unknown credential_type or organization or existing credential
        return None

    def credentials_update(self, name, credential_type_name, organization_name, inputs):
        # GET credential
        credential = self.credentials_get(name=name)

        # GET credential_type
        credential_type = self.credential_types_get(name=credential_type_name)

        # GET organization
        organization = self.organizations_get(name=organization_name)

        # UPDATE credential
        if len(credential['results']) == 1 and \
                len(credential_type['results']) == 1 and \
                len(organization['results'] == 1):

            path = '/api/v2/credentials/' + credential['results'][0]['id'] + '/'
            data = {
                'name': name,
                'description': 'Updated by CMP',
                'organization': organization['results'][0]['id'],
                'credential_type': credential_type['results'][0]['id'],
                'inputs': inputs
            }
            return self._patch(path, data)

        # Unknown credential_type or organization or existing credential
        return None

    def credentials_delete(self, name, credential_type_name, organization_name, inputs):
        # GET credential
        credential = self.credentials_get(name=name)

        # UPDATE credential
        if len(credential['results']) == 1:
            path = '/api/v2/credentials/' + credential['results'][0]['id'] + '/'
            return self._delete(path)

        # Unknown credential
        return None

    def workflow_job_template_nodes_get(self, wf_tpl_name=None, job_tpl_name=None):
        path = '/api/v2/workflow_job_template_nodes/'
        parameters = []

        # Filtering
        if wf_tpl_name:
            parameter = 'workflow_job_template__name=' + wf_tpl_name
            parameters.append(parameter)
        if job_tpl_name:
            parameter = 'unified_job_template__name=' + job_tpl_name
            parameters.append(parameter)

        return self._get(path, parameters)

    def workflow_jobs__id__workflow_nodes(self, wf_job_id=None):
        path = '/api/v2/workflow_jobs/' + str(wf_job_id) + '/workflow_nodes/'

        # Pagination
        parameters = ['page_size=100']

        return self._get(path, parameters)

    def workflow_jobs__id(self, wf_job_id=None):
        path = '/api/v2/workflow_jobs/' + str(wf_job_id) + '/'
        return self._get(path)

    def workflow_job_templates_get(self, name=None):
        path = '/api/v2/workflow_job_templates/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def workflow_job_templates__id_get(self, name=None):
        # GET workflow
        wf = self.workflow_job_templates_get(name)
        path = '/api/v2/workflow_job_templates/' + str(wf['results'][0]['id']) + '/'
        parameters = []

        return self._get(path, parameters)

    def workflow_job_templates__id_launch(self, name, extra_vars=None, verbosity=0):
        # GET job tpl
        wf = self.workflow_job_templates__id_get(name)

        # SET attribute
        url = '/api/v2/workflow_job_templates/' + str(wf['id']) + '/launch/'
        data = {}
        if extra_vars:
            data['extra_vars'] = extra_vars

        return self._post(url, data)

    def workflow_job_templates__id_delete(self, name=None):
        # GET workflow
        wf = self.workflow_job_templates_get(name)
        if len(wf['results']) > 0:
            path = '/api/v2/workflow_job_templates/' + str(wf['results'][0]['id']) + '/'
            parameters = []

            # URL builder
            if len(parameters) > 0:
                url = path + '?' + '&'.join(parameters)
            else:
                url = path
            return self._delete(url)
        else:
            return None

    def workflow_job_templates__id_update(self, cur_name, new_name=None):
        # GET workflow
        wf = self.workflow_job_templates_get(cur_name)
        path = '/api/v2/workflow_job_templates/' + str(wf['results'][0]['id']) + '/'

        # SET workflow node attribute
        data = {}
        if new_name:
            data['name'] = new_name

        return self._patch(path, data)

    def workflow_job_templates__id__copy(self, wf_tpl_name_original, wf_tpl_name_copy, sync=True):
        # GET workflow
        wf_original = self.workflow_job_templates_get(wf_tpl_name_original)
        wf_original_nodes = self.workflow_job_template_nodes_get(wf_tpl_name_original)['results']

        # COPY workflow original
        url = '/api/v2/workflow_job_templates/' + str(wf_original['results'][0]['id']) + '/copy/'
        data = {'name': wf_tpl_name_copy}
        wf_copy = self._post(url, data)

        # wait for nodes copy
        for cur_original_node in wf_original_nodes:
            wf_copy_cur_node = self.workflow_job_template_nodes_get(
                wf_tpl_name=wf_tpl_name_copy,
                job_tpl_name=cur_original_node['summary_fields']['unified_job_template']['name']
            )
            while len(wf_copy_cur_node['results']) == 0:
                time.sleep(1)
                wf_copy_cur_node = self.workflow_job_template_nodes_get(
                    wf_tpl_name=wf_tpl_name_copy,
                    job_tpl_name=cur_original_node['summary_fields']['unified_job_template']['name']
                )

        return wf_copy

    def workflow_job_template_nodes__id_update(self, wf_tpl_name, job_tpl_name, inventory_name=None, limit=None, verbosity=None):
        # GET node
        node = self.workflow_job_template_nodes_get(wf_tpl_name, job_tpl_name)

        path = '/api/v2/workflow_job_template_nodes/' + str(node['results'][0]['id']) + '/'

        # SET workflow node attribute
        data = {}
        if inventory_name:
            data['inventory'] = self.inventories_get(name=inventory_name)['results'][0]['id']
        if limit:
            data['limit'] = limit
        if verbosity:
            data['verbosity'] = verbosity

        return self._patch(path, data)

    def workflow_job_template_nodes__id__credentials_get(self, id_node):
        path = '/api/v2/workflow_job_template_nodes/' + str(id_node) + '/credentials/'

        return self._get(path)

    def workflow_job_template_nodes__id__credentials_create(self, wf_tpl_name, job_tpl_name, credential_name):
        # GET node
        node = self.workflow_job_template_nodes_get(wf_tpl_name, job_tpl_name)

        # GET credential
        credential = self.credentials_get(name=credential_name)

        # ADD workflow node credential
        url = '/api/v2/workflow_job_template_nodes/' + str(node['results'][0]['id']) + '/credentials/'
        data = {'id': credential['results'][0]['id']}

        return self._post(url, data)

    def workflow_job_template_nodes__id__credentials_delete(self, wf_tpl_name, job_tpl_name, credential_name):
        # GET node
        node = self.workflow_job_template_nodes_get(wf_tpl_name, job_tpl_name)

        # GET credential
        credential = self.credentials_get(name=credential_name)

        # DELETE workflow node credential
        url = '/api/v2/workflow_job_template_nodes/' + str(node['results'][0]['id']) + '/credentials/'
        data = {
            'id': credential['results'][0]['id'],
            'disassociate': True
        }

        return self._post(url, data)

    def job_templates_get(self, name=None):
        path = '/api/v2/job_templates/'
        parameters = []

        # Filtering
        if name:
            parameter = 'name=' + name
            parameters.append(parameter)

        return self._get(path, parameters)

    def jobs__id(self, job_id=None):
        path = '/api/v2/jobs/' + str(job_id) + '/'
        return self._get(path)

    def jobs__id__stdout(self, job_id, format_stdout='json'):
        path = '/api/v2/jobs/' + str(job_id) + '/stdout/'
        parameters = []

        # Format
        parameter = 'format=' + format_stdout
        parameters.append(parameter)

        return self._get(path, parameters)

    def job_templates__id__credentials_get(self, id_job_tpl, credential_name):
        path = '/api/v2/job_templates/' + str(id_job_tpl) + '/credentials/'
        parameters = []

        # Filtering
        if credential_name:
            parameter = 'name=' + credential_name
            parameters.append(parameter)

        return self._get(path, parameters)

    def job_templates__id__credentials_create(self, id_job_tpl, credential_name):
        # GET credential
        credential = self.credentials_get(name=credential_name)

        # ADD job tpl credential
        if len(self.job_templates__id__credentials_get(id_job_tpl=id_job_tpl, credential_name=credential_name)['results']) == 0:
            url = '/api/v2/job_templates/' + str(id_job_tpl) + '/credentials/'
            data = {'id': credential['results'][0]['id']}
            return self._post(url, data)

        # Credential already attached to job tpl
        else:
            return None

    def job_templates__id__launch(self, name, inventory=None, credential=None, extra_vars=None, verbosity=0, limit=None):
        # GET job tpl
        job_tpl = self.job_templates_get(name)

        # SET Credential
        self.job_templates__id__credentials_create(
            id_job_tpl=job_tpl['results'][0]['id'],
            credential_name=credential)

        # SET attribute
        url = '/api/v2/job_templates/' + str(job_tpl['results'][0]['id']) + '/launch/'
        if limit is not None:
            data = {
                'verbosity': verbosity,
                'limit': limit
            }
        else:
            data = {
                'verbosity': verbosity,
            }
        if inventory:
            data['inventory'] = self.inventories_get(name=inventory)['results'][0]['id']
        if credential:
            data['credential'] = self.credentials_get(name=credential)['results'][0]['id']
        if extra_vars:
            data['extra_vars'] = extra_vars

        return self._post(url, data)


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


if __name__ == '__main__':
    # Parameters
    debug = True
    verbose = True
    log_file = 'tests.log'

    # Logging settings
    global logger
    logger = setup_logging(debug, verbose, log_file)
    tower_session = TowerApi(
        host='212.121.177.199',
        username='pycharm',
        password='PyCh4rm',
        client_id='obgQYVVoOeGZ6PoVuoyeYXHyglrHFAx7ZHysp5F0',
        client_secret='JnbyMNlgGlWX1zZ5A3OmHAUQ5e8UI2vdO15SqDCgj85eEHYM74jgad5BnQ6vVuHmVkFNEmb3MZNk8xEXeJNm1br5gvvbIQQRwlbpYnxrtgxkboRwgaIWR18GWntIdArW',
        logger=logger
    )
    tower_session.get_token()
    # r = tower_session.inventories_get(name='CMP_inv_CloudBuilderf5')
    # r = tower_session.inventories_get(name='localhost')
    # r = tower_session.credentials_get(name='CMP_cred_microsoft-azure-resource-manager_CloudBuilderf5')
    # node = tower_session.workflow_job_template_nodes_get(
    # wf_tpl_name='wf-create-app_waf-CloudBuilderf5-app1spoke1', job_tpl_name='poc-azure_create_vmss_app'
    # )
    # r = tower_session.workflow_job_template_nodes__id__credentials_add(
    # id_node=node['results'][0]['id'], name='CMP_cred_microsoft-azure-resource-manager_CloudBuilderf5'
    # )
    # r = tower_session.workflow_job_template_nodes__id__credentials_delete(
    # id_node=node['results'][0]['id'], name='CMP_cred_microsoft-azure-resource-manager_CloudBuilderf5'
    # )
    # r = tower_session.workflow_job_template_nodes__id__credentials_get(id_node=node['results'][0]['id'])
    # r = tower_session.workflow_job_templates_get(wf_tpl_name='wf-create-app_waf-TEST')
    # r = tower_session.workflow_job_templates__id__copy(
    # wf_tpl_name_original='wf-create-app_waf', wf_tpl_name_copy='wf-create-app_waf-TEST'
    # )

    name = "poc-f5_url_category-remove_url"
    inventory = "CMP_inv_CloudBuilderf5"
    credential = "CMP_cred_microsoft-azure-resource-manager_CloudBuilderf5"
    extra_vars = {
        "activity": "url_category-remove_url",
        "extra_admin_user": "admin",
        "extra_admin_password": "F5N3tworks!",
        "extra_ip_mgt": "10.228.234.11",
        "extra_port_mgt": 443,
        "extra_category": "total_cat_a",
        "extra_url_name": "*www.test3.com*",
        "extra_url_type": "glob-match",
    }

    # CREATE job
    r = tower_session.job_templates__id__launch(
        name,
        inventory=inventory,
        credential=credential,
        extra_vars=extra_vars,
        verbosity=1,
        limit='sslo1'
    )
    import pprint
    pprint.pprint("job ID: %s" % r['id'])

    # GET stdout
    """
    job_id = 11
    r = tower_session.jobs__id__stdout(job_id=r['id'])
    import pprint
    pprint.pprint("stdout: %s" % r)
    """
