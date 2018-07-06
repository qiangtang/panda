import json
import logging

from restclient import RestClient


class OmsController(object):
    # Helper methods

    def __init__(self, oms, sso_user, sso_pwd):
        self.rest_client = RestClient(oms, sso_user, sso_pwd)
        self.logger = logging.getLogger(__name__)

        self._made_remote_dirs = []

    def login(self):
        self.rest_client.login()

    def hello(self):
        return self.rest_client.do_get('hello')

    def server_version(self):
        return self.rest_client.do_get('version')

    def server_status(self):
        return self.rest_client.do_get('status')

    def list_task(self):
        return self.rest_client.do_get('tasks')

    def list_networks(self):
        response = self.rest_client.do_get("networks")
        return response

    def list_datastores(self):
        response = self.rest_client.do_get("datastores")
        return response

    def list_deployments(self):
        clusters = self.rest_client.do_get('clusters')
        return clusters

    def list_deployment(self, name):
        api_url_template = "cluster/{}"
        url = api_url_template.format(name)
        cluster = self.rest_client.do_get(url)
        return cluster

    def delete_deployment(self, deployment_name):
        return self.rest_client.do_delete('cluster', deployment_name)

    def create_deployment_by_spec(self, deployment_json):
        resp = self._create_deployment(deployment_json)
        return resp

    def _create_deployment(self, spec):
        post_body = json.dumps(spec)
        resp = self.rest_client.do_post('clusters', post_body)
        return resp

    def add_compute_vc(self, spec):
        post_body = json.dumps(spec)
        resp = self.rest_client.do_post('vc', post_body)
        return resp

    def get_vc_ip(self):
        resp = self.rest_client.do_get('vcip')
        return resp

    def cluster_config(self, spec):
        resp = self.rest_client.do_put("cluster/VIO/config", spec)
        return resp

    def get_task(self, taskid):
        task = self.rest_client.do_get('task/{}'.format(taskid))
        return json.loads(task.text)

    def del_nova_datastore(self, spec):
        resp = self.rest_client.do_put("clusters/VIO/novadatastore", spec)
        return resp

    def del_glance_datastore(self, spec):
        resp = self.rest_client.do_put("clusters/VIO/glancedatastore", spec)
        return resp

    def retry_cluster(self, cluster, spec):
        api_url_template = "clusters/%s?action=retry"
        url = api_url_template % cluster
        put_body = json.dumps(spec)
        resp = self.rest_client.do_put(url, put_body)
        return resp

    def retrieve_cluster_profile(self, cluster):
        api_url_template = "clusters/%s/profile"
        url = api_url_template % cluster
        resp = self.rest_client.do_get(url)
        return resp

    def create_deployment_plan(self, spec):
        resp = self.rest_client.do_put("clusters/plan", spec)
        return resp

    def add_nova_node_plan(self, cluster, ng):
        api_url_template = "cluster/{}/nodegroup/{}/plan"
        url = api_url_template.format(cluster, ng)
        resp = self.rest_client.do_put(url, str(2))  # totalInstanceNum
        return resp

    def add_nova_node(self, cluster, ng, spec):
        api_url_template = "cluster/{}/nodegroup/{}/scaleout"
        url = api_url_template.format(cluster, ng)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def add_node_group(self, cluster, spec):
        api_url_template = "clusters/{}/nodegroups"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_post(url, spec)
        return resp

    def del_nova_node(self, cluster, ng, nd):
        api_url_template = "cluster/{}/nodegroup/{}/node"
        url = api_url_template.format(cluster, ng)
        resp = self.rest_client.do_delete(url, nd)
        return resp

    def increase_ips(self, nw, spec):
        api_url_template = "network/{}"
        url = api_url_template.format(nw)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def update_dns(self, nw, spec):
        api_url_template = "network/{}/async"
        url = api_url_template.format(nw)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def get_sysconf(self):
        resp = self.rest_client.do_get("conf")
        return json.loads(resp.text)

    def set_syslogserver(self, logserver, port, protocol, tag):
        url = \
            'conf?syslogserver={}&syslogserverport={}' \
            '&syslogserverprotocol={}&syslogservertag={}'
        resp = self.rest_client.do_put(
            url.format(
                logserver, port, protocol, tag), "")
        return resp

    def get_network_by_name(self, networkname):
        resp = self.rest_client.do_get("network/{}".format(networkname))
        return json.loads(resp.text)

    def create_support_bundle(self, spec):
        resp = self.rest_client.do_post("bundles", spec)
        return resp

    def get_support_bundle(self, spec, dest):
        resp = self.rest_client.do_post("bundles", spec)
        fileName = resp.text.split('/')[-1][0:-1]
        with open('%s/%s' % (dest, fileName), 'wb') as handle:
            resp = self.rest_client.do_get("bundle/{}".format(fileName))
            for block in resp.iter_content(1024):
                if not block:
                    break
                handle.write(block)
        return fileName

    def validate(self, type, spec):
        api_url_template = "validators/{}"
        url = api_url_template.format(type)
        put_body = json.dumps(spec)
        resp = self.rest_client.do_post(url, put_body)
        return resp

    def manage_openstack_services(self, cluster, service, action):
        api_url_template = "clusters/{}/services/{}?action={}"
        url = api_url_template.format(cluster, service, action)
        resp = self.rest_client.do_put(url, None)
        return resp

    def start_services(self, cluster, spec):
        api_url_template = "clusters/{}/services?action=start"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def stop_services(self, cluster, spec):
        api_url_template = "clusters/{}/services?action=stop"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def restart_services(self, cluster, spec):
        api_url_template = "clusters/{}/services?action=restart"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_put(url, spec)
        return resp

    def generate_csr(self, clusterName, spec):
        api_url_template = "clusters/{}/csr"
        url = api_url_template.format(clusterName)
        resp = self.rest_client.do_post(url, spec)
        return resp

    def add_horizon(self, cluster, spec):
        api_url_template = "clusters/{}/horizon"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_post(url, spec)
        return resp

    def del_horizon(self, cluster, title):
        api_url_template = "clusters/{}/horizon"
        url = api_url_template.format(cluster)
        resp = self.rest_client.do_delete(url, title)
        return resp

    def list_horizon(self, cluster):
        api_url_template = "clusters/{}/horizon"
        url = api_url_template.format(cluster)
        regions = self.rest_client.do_get(url)
        return regions

    def get_plugin_status(self):
        url = "plugin/status"
        resp = self.rest_client.do_get(url)
        return resp

    def check_oms_vc_connection(self):
        url = "checkOmsVCConnection"
        resp = self.rest_client.do_get(url)
        return resp

    def get_oms_vc_status(self):
        url = "connection/status"
        resp = self.rest_client.do_get(url)
        return resp

    def register_plugin(self):
        url = "plugin/register?addException=true"
        resp = self.rest_client.do_post(url, "")
        return resp

    def change_datacollector_setting(self, enable="false"):
        api_url_template = "datacollector?enabled={}"
        url = api_url_template.format(enable)
        resp = self.rest_client.do_post(url, "")
        return resp

    def get_datacollector_setting(self):
        url = "datacollector"
        resp = self.rest_client.do_get(url)
        return resp

    def get_audit_file(self):
        url = "phauditfile"
        resp = self.rest_client.do_get(url)
        return resp

    def start_cluster(self, cluster):
        api_url_template = "cluster/%s?action=start"
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, "")
        return resp

    def stop_cluster(self, cluster):
        api_url_template = "cluster/%s?action=stop"
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, "")
        return resp

    def upgrade_provision(self, cluster, spec):
        post_body = json.dumps(spec)
        api_url_template = '/clusters/%s/upgrade/provision'
        url = api_url_template % cluster
        resp = self.rest_client.do_post(url, post_body)
        return resp

    def upgrade_retry(self, cluster, spec):
        put_body = json.dumps(spec)
        api_url_template = '/clusters/%s/upgrade/retry'
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, put_body)
        return resp

    def upgrade_migrate_data(self, cluster):
        api_url_template = '/clusters/%s/upgrade/configure'
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, "")
        return resp

    def upgrade_switch_to_green(self, cluster):
        api_url_template = '/clusters/%s/upgrade/switch'
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, "")
        return resp

    def switch_keystone_backend(self, cluster, spec):
        put_body = json.dumps(spec)
        api_url_template = '/clusters/%s/keystonebackend'
        url = api_url_template % cluster
        resp = self.rest_client.do_put(url, put_body)
        return resp

