import json
import logging
import re
import commands
from exceptions import ProvisionError
from exceptions import NotCompletedError
from exceptions import NotFoundError
from pyVmomiwrapper.vmwareapi import VirtualCenter
from pyVmomiwrapper.vmwareapi import DataStore
from pyVmomiwrapper.vmwareapi import DistributedVirtualSwitch

LOG = logging.getLogger(__name__)
DVS_BACKEND = 'dvs'
NSXV_BACKEND = 'nsxv'
NSXV3_BACKEND = 'nsxv3'
VCENTER_PORT = 443
LDAP_BACKEND = 'ldap'
ANSIBLE_ERROR = 'Ansible error'


def is_legacy_spec(cluster_spec):
    # True for cluster spec before 4.0
    if 'nodeGroups' in cluster_spec:
        return True
    else:
        return False


def get_nodegroup_by_name(cluster_spec, name):
    for node_group in cluster_spec['nodeGroups']:
        if node_group['name'] == name:
            return node_group


def get_nodegroup_by_role(cluster_spec, role):
    for node_group in cluster_spec['nodeGroups']:
        roles = node_group.get('roles') or [node_group['role']]
        if role in roles:
            return node_group


def get_neutron_backend(cluster_spec):
    if is_legacy_spec(cluster_spec):
        # 4.0
        controller = get_nodegroup_by_role(cluster_spec, 'Controller')
        return controller['attributes']['neutron_backend']
    else:
        # 4.1
        ne_back = cluster_spec['openstack_info']['network']['neutron_backend']
        return ne_back.lower()


def create_deployment_plan(oms_ctl, cluster_spec):
    if is_legacy_spec(cluster_spec):
        LOG.info('Create OpenStack cluster deployment plan.')
        # This is a workaround due to oms api design inconsistency.
        data_network = cluster_spec['networkConfig']['DATA_NETWORK']
        controller = get_nodegroup_by_role(cluster_spec, 'Controller')
        if DVS_BACKEND == controller['attributes']['neutron_backend']:
            cluster_spec['networkConfig']['DATA_NETWORK'] = \
                cluster_spec['networkConfig']['MGT_NETWORK']
        spec_str = json.dumps(cluster_spec)
        resp = oms_ctl.create_deployment_plan(spec_str)
        if resp.status_code == 200:
            LOG.debug("Deployment plan: %s" % resp.text)
            cluster_spec['attributes']['plan'] = resp.text
        else:
            LOG.error("Failed to create deployment plan: %s" % resp.text)
            raise ProvisionError("Failed to create deployment plan!")
        if DVS_BACKEND == controller['attributes']['neutron_backend']:
            cluster_spec['networkConfig']['DATA_NETWORK'] = data_network
        return cluster_spec
    else:
        return cluster_spec


def delete_cluster(oms_ctl, name="VIO"):
    LOG.info('Deleting Openstack cluster %s' % name)
    oms_ctl.delete_deployment(name)


def check_creation_completed(oms_ctl, cluster_name):
    if not check_cluster_status(oms_ctl, cluster_name,
                                ["RUNNING", "PROVISION_ERROR"]):
        raise NotCompletedError("Provisioning is not completed")


def get_cluster(oms_ctl, cluster_name):
    clusters_resp = oms_ctl.list_deployments()
    LOG.debug('clusters_resp: {}'.format(clusters_resp))
    clusters = clusters_resp.json()
    for cluster in clusters:
        if cluster['name'] == cluster_name:
            return cluster
    raise NotFoundError('Cluster %s not Found.' % cluster_name)


def get_private_vip(oms_ctl, cluster_name):
    cluster = get_cluster(oms_ctl, cluster_name)
    load_balance = get_nodegroup_by_role(cluster, 'LoadBalancer')
    private_vip = load_balance['attributes']['internal_vip']
    LOG.debug('Private VIP: %s' % private_vip)
    return private_vip


def get_public_vip(oms_ctl, cluster_name):
    cluster = get_cluster(oms_ctl, cluster_name)
    load_balance = get_nodegroup_by_role(cluster, 'LoadBalancer')
    public_vip = load_balance['attributes']['public_vip']
    LOG.debug('Public VIP: %s' % public_vip)
    return public_vip


def get_node_error(oms_ctl, cluster_name):
    cluster = get_cluster(oms_ctl, cluster_name)
    groups = cluster['nodeGroups']
    for group in groups:
        for instance in group['instances']:
            if instance['status'] == 'Bootstrap Failed':
                return ANSIBLE_ERROR
    return 'OMS java error'


def check_cluster_status(oms_ctl, cluster_name, status_list):
    cluster = get_cluster(oms_ctl, cluster_name)
    status = cluster['status']
    LOG.debug('Cluster status: %s' % status)
    if status in status_list:
        return True
    return False


def check_deployment(oms_ctl, cluster_name):
    if check_cluster_status(oms_ctl, cluster_name, ['RUNNING']):
        LOG.info('Successfully deployed OpenStack Cluster.')
    else:
        LOG.error('Openstack cluster status is not running!')
        cause = get_node_error(oms_ctl, cluster_name)
        LOG.error('Detected %s' % cause)
        raise ProvisionError(cause)


def retry_ansible(oms_ctl, cluster_spec, version):
    LOG.info('Retry provisioning cluster.')
    if int(version[0]) >= 3:
        oms_ctl.retry_cluster(cluster_spec['name'])
    else:
        oms_ctl.legacy_retry_cluster(cluster_spec['name'], cluster_spec)


def get_vc_fingerprint(vcenter_ip):
    cmd = "echo -n | openssl s_client -connect {}:443 2>/dev/null " \
          "| openssl x509 -noout -fingerprint -sha1"
    result = commands.getoutput(cmd.format(vcenter_ip)).split('=')
    if result and len(result) > 1:
        return result[1]
    else:
        return None


# def get_vc_fingerprint(vcenter_ip):
#     cert_pem = ssl.get_server_certificate((vcenter_ip, VCENTER_PORT),
#                                           ssl_version=ssl.PROTOCOL_TLSv1)
#     from M2Crypto import X509
#     x509 = X509.load_cert_string(cert_pem, X509.FORMAT_PEM)
#     fp = x509.get_fingerprint('sha1')
#     return ':'.join(a + b for a, b in zip(fp[::2], fp[1::2]))


def add_compute_vc(oms_ctl, ssh_client, vcenter_insecure,
                   vcenter_ip, vc_user, vc_pwd):
    LOG.info('Add compute VC %s.', vcenter_ip)
    fp = get_vc_fingerprint(vcenter_ip)
    if vcenter_insecure == 'false' and \
            re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', vcenter_ip):
        vc_host = get_fqdn(ssh_client, vcenter_ip)
    else:
        vc_host = vcenter_ip
    spec = {'hostname': vc_host,
            'port': VCENTER_PORT,
            'username': vc_user,
            'password': vc_pwd,
            'thumbprint': fp}
    LOG.debug("Spec of compute VC: %s" % spec)
    resp = oms_ctl.add_compute_vc(spec)
    if resp.status_code != 200:
        raise ProvisionError('Failed to add compute cluster. Spec: %s. '
                             'resp text %s' % (spec, resp.text))
    LOG.info('Successfully added compute cluster. Spec: %s.', spec)


def add_glance_ds(oms_ctl, ssh_client, vcenter_insecure,
                  vcenter_ip, vc_user, vc_pwd, vc_dc):
    with VirtualCenter(vcenter_ip, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(vc_dc)
        glance_obj = dc_mor.get_entity_by_name(DataStore,
                                               'vdnetSharedStorage')
        glance_ds_moid = glance_obj.moid
    if vcenter_insecure == 'false' and \
            re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', vcenter_ip):
        vcenter_fqdn = get_fqdn(ssh_client, vcenter_ip)
    else:
        vcenter_fqdn = vcenter_ip
    glance_ds = "null:Datastore:%s" % glance_ds_moid
    spec = {
        "roles": [
            {
                "attributes": {
                    "glance_replication_datastores": glance_ds,
                    "vcenter_glance_ip": vcenter_fqdn
                },
                "role_names": [
                    "Controller"
                ]
            }
        ]
    }
    spec = json.dumps(spec)
    try:
        oms_ctl.cluster_config(spec)
    except Exception as e:
        raise ProvisionError('Failed to add glance datastore. Spec: %s. '
                             'resp text %s' % (spec, e.message))
    # wait for task completed
    LOG.info('Successfully added glance datastore. Spec: %s.', spec)


def add_compute(oms_ctl, cluster_name, ssh_client, vcenter_insecure,
                vcenter_ip, vc_user, vc_pwd, vc_dc):
    compute_moid = get_cluster_moid(vcenter_ip, vc_user, vc_pwd,
                                    vc_dc, 'compute_cluster')
    if vcenter_insecure == 'false' and \
            re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', vcenter_ip):
        vcenter_fqdn = get_fqdn(ssh_client, vcenter_ip)
    else:
        vcenter_fqdn = vcenter_ip
    spec = [
        {
            "cluster_name": "compute_cluster",
            "datastore_regex": "vdnetSharedStorage",
            "cluster_moid": compute_moid,
            "vcenter_ip": vcenter_fqdn,
            "is_management_vc": "false",
            "availability_zone_name": "az-2"
        }]
    spec = json.dumps(spec)
    try:
        cluster_spec = get_cluster(oms_ctl, cluster_name)
        compute_node = get_nodegroup_by_role(cluster_spec,
                                             'Compute')
        oms_ctl.add_nova_node(cluster_spec['name'], compute_node['name'], spec)
    except Exception as e:
        raise ProvisionError('Failed to add nova node. Spec: %s. '
                             'resp text %s' % (spec, e.message))
    LOG.info('Successfully added nova node. Spec: %s.', spec)


def get_cluster_moid(vc_host, vc_user, vc_pwd, datacenter, cluster):
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        return dc_mor.get_cluster(cluster).moid


def get_moids(vc_host, vc_user, vc_pwd, datacenter, mgmt_cluster,
              compute_clusters, datastore):
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        mgmt_moid = dc_mor.get_cluster(mgmt_cluster).moid
        compute_moids = []
        for compute in compute_clusters:
            compute_moids.append(dc_mor.get_cluster(compute).moid)
        ds_moid = dc_mor.get_entity_by_name(DataStore, datastore).moid

        return mgmt_moid, compute_moids, ds_moid


def _set_compute_driver(compute_group, compute_morefs, vcenter_ip=None):
    if 'nodeAttributes' in compute_group:
        node_attributes = compute_group['nodeAttributes']
    else:
        node_attributes = compute_group['compute_clusters']
    count = 0
    for attribute in node_attributes:
        # This is very bad design since cluster_moid is different format in
        # multiple and single VC
        if 'vcenter_ip' in attribute:
            attribute['vcenter_ip'] = vcenter_ip
        attribute['cluster_moid'] = compute_morefs[count]
        count += 1


def _set_image_driver(image_group, vc_host):
    node_attributes = image_group['datastores']
    for attribute in node_attributes:
        if 'vcenter_ip' in attribute:
            attribute['vcenter_ip'] = vc_host


def refresh_nsxv_config(cluster_spec, nsxv_ip, nsxv_user, nsxv_pwd):
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
        ctl_attrs['nsxv_manager'] = nsxv_ip
        ctl_attrs['nsxv_username'] = nsxv_user
        ctl_attrs['nsxv_password'] = nsxv_pwd
    else:
        network = cluster_spec['openstack_info']['network']['nsxv']
        network['nsxv_manager'] = nsxv_ip
        network['nsxv_username'] = nsxv_user
        network['nsxv_password'] = nsxv_pwd


def refresh_nsxv3_config(cluster_spec, nsxv3_ip, nsxv3_user, nsxv3_pwd):
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
        # TODO: support multiple nsx managers
        ctl_attrs['nsxv3_api_managers'] = nsxv3_ip
        ctl_attrs['nsxv3_api_username'] = nsxv3_user
        ctl_attrs['nsxv3_api_password'] = nsxv3_pwd
    else:
        network = cluster_spec['openstack_info']['network']['nsxv3']
        network['nsxv3_api_managers'] = nsxv3_ip
        network['nsxv3_api_username'] = nsxv3_user
        network['nsxv3_api_password'] = nsxv3_pwd


def refresh_nsxv3_compute_moid(cluster_spec, vc_host, vc_user, vc_pwd,
                               datacenter, compute_clusters):
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        LOG.debug('Compute dc: %s, MOID: %s', datacenter, dc_mor.moid)
        compute_moids = []
        for compute in compute_clusters:
            cls_moid = dc_mor.get_cluster(compute).moid
            LOG.debug('Compute cluster: %s, MOID: %s', compute, cls_moid)
            compute_moids.append(cls_moid)
    if is_legacy_spec(cluster_spec):
        # Set compute driver group
        compute_group = get_nodegroup_by_role(cluster_spec, 'Compute')
    else:
        compute_group = cluster_spec['openstack_info']['compute']
        _set_image_driver(cluster_spec['openstack_info']['image'], vc_host)
    _set_compute_driver(compute_group, compute_moids, vc_host)


def refresh_mgmt_moid(cluster_spec, vc_host, vc_user, vc_pwd, datacenter,
                      mgmt_cluster):
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        mgmt_cls_moid = dc_mor.get_cluster(mgmt_cluster).moid
    LOG.debug('Management dc: %s, MOID: %s', datacenter, dc_mor.moid)
    LOG.debug('Management cluster: %s, MOID: %s', mgmt_cluster, mgmt_cls_moid)
    # Set management cluster mo id.
    if 'vcClusters' in cluster_spec:
        cluster_spec['vcClusters'][0]['moid'] = mgmt_cls_moid
    elif 'management_cluster' in cluster_spec:
        cluster_spec['management_cluster']['moid'] = mgmt_cls_moid


def refresh_nodegroup_nsxv_moid(cluster_spec, vc_host, vc_user, vc_pwd,
                                datacenter, compute_clusters, glance_ds,
                                nsxv_edge_dvs, nsxv_edge_cluster):
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
    else:
        ctl_attrs = cluster_spec['openstack_info']['network']['nsxv']
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        LOG.debug('Compute dc: %s, MOID: %s', datacenter, dc_mor.moid)
        compute_moids = []
        for compute in compute_clusters:
            cls_moid = dc_mor.get_cluster(compute).moid
            LOG.debug('Compute cluster: %s, MOID: %s', compute, cls_moid)
            compute_moids.append(cls_moid)
        edge_dvs_moid = dc_mor.get_entity_by_name(DistributedVirtualSwitch,
                                                  nsxv_edge_dvs).moid
        LOG.debug('Edge dvs: %s, MOID: %s', nsxv_edge_dvs, edge_dvs_moid)
        edge_cluster_moid = dc_mor.get_cluster(nsxv_edge_cluster).moid
        LOG.debug('Edge cluster: %s, MOID: %s', nsxv_edge_cluster,
                  edge_cluster_moid)
        # This is very bad design in cluster spec, only multiple VCs need to
        # get glance ds mo id and set it like "null:Datastore:datastore-12". In
        # single VC, ds name is used "vio-datacenter:vdnetSharedStorage:100".
        if glance_ds and is_legacy_spec(cluster_spec):
            glance_ds_moid = dc_mor.get_entity_by_name(DataStore,
                                                       glance_ds).moid
            LOG.debug('Glance ds: %s, MOID: %s', glance_ds, glance_ds_moid)
            ctl_attrs['glance_datastores'] = 'null:Datastore:%s' % \
                                             glance_ds_moid
    # Set controller group
    ctl_attrs['nsxv_edge_cluster_moref'] = edge_cluster_moid
    ctl_attrs['nsxv_dvs_moref'] = edge_dvs_moid
    if is_legacy_spec(cluster_spec):
        # Set compute driver group
        compute_group = get_nodegroup_by_role(cluster_spec, 'Compute')
    else:
        compute_group = cluster_spec['openstack_info']['compute']
        _set_image_driver(cluster_spec['openstack_info']['image'], vc_host)
    _set_compute_driver(compute_group, compute_moids, vc_host)


def refresh_nodegroup_dvs_moid(cluster_spec, vc_host, vc_user, vc_pwd,
                               datacenter, compute_clusters, dvs):
    with VirtualCenter(vc_host, vc_user, vc_pwd) as vc:
        dc_mor = vc.get_datacenter(datacenter)
        compute_moids = []
        for compute in compute_clusters:
            cls_moid = dc_mor.get_cluster(compute).moid
            LOG.debug('Compute cluster: %s, MOID: %s', compute, cls_moid)
            compute_moids.append(cls_moid)
    # Set controller group
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
        ctl_attrs['dvs_default_name'] = dvs
        # Set compute driver group
        compute_group = get_nodegroup_by_role(cluster_spec, 'Compute')
    else:
        compute_group = cluster_spec['openstack_info']['compute']
        _set_image_driver(cluster_spec['openstack_info']['image'], vc_host)
    _set_compute_driver(compute_group, compute_moids)


def refresh_vc_config(cluster_spec, vc_host, vc_user, vc_pwd):
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
        ctl_attrs['vcenter_ip'] = vc_host
        ctl_attrs['vcenter_user'] = vc_user
        ctl_attrs['vcenter_password'] = vc_pwd
    else:
        cluster_spec['vcenters'][0]['hostname'] = vc_host
        cluster_spec['vcenters'][0]['username'] = vc_user
        cluster_spec['vcenters'][0]['password'] = vc_pwd


def set_vc_fqdn(cluster_spec, ssh_client):
    if is_legacy_spec(cluster_spec):
        ctl_attrs = get_controller_attrs(cluster_spec)
        vc_host = ctl_attrs['vcenter_ip']
        vcenter_insecure = ctl_attrs.get('vcenter_insecure', '')
    else:
        vc_host = cluster_spec['vcenters'][0]['hostname']
        vcenter_insecure = cluster_spec['openstack_info']['vcenter_insecure']
    if vcenter_insecure == 'false' and re.match(
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', vc_host):
        fqdn = get_fqdn(ssh_client, vc_host)
        LOG.debug('vCenter IP: %s, change it to FQDN: %s', vc_host, fqdn)
        if is_legacy_spec(cluster_spec):
            ctl_attrs['vcenter_ip'] = fqdn
            for compute in get_nodegroup_by_role(
                    cluster_spec, 'Compute')['nodeAttributes']:
                if 'vcenter_ip' in compute:
                    compute['vcenter_ip'] = fqdn
        else:
            cluster_spec['vcenters'][0]['hostname'] = fqdn
            image_node = cluster_spec['openstack_info']['image']
            image_node['datastores'][0]['vcenter_ip'] = fqdn
            compute_group = cluster_spec['openstack_info']['compute']
            for compute in compute_group['compute_clusters']:
                if 'vcenter_ip' in compute:
                    compute['vcenter_ip'] = fqdn


def get_fqdn(ssh_client, vc_host):
    return ssh_client.run('python -c \'import socket; print socket.getfqdn'
                          '("%s")\'' % vc_host).replace('\n', '')


def refresh_syslog_tag(cluster_spec, build_id):
    if not is_legacy_spec(cluster_spec):
        return
    ctl_attrs = get_controller_attrs(cluster_spec)
    if 'syslog_server_tag' in ctl_attrs:
        if ctl_attrs['neutron_backend'] == NSXV_BACKEND:
            ctl_attrs['syslog_server_tag'] = 'NSXV-%s' % build_id
        else:
            ctl_attrs['syslog_server_tag'] = 'DVS-%s' % build_id


def get_controller_attrs(cluster_spec):
    return get_nodegroup_by_role(cluster_spec, 'Controller')['attributes']


def add_ip_addresses(oms_ctl, network_name, begin_ip, end_ip):
    LOG.info("Add %s-%s to network %s", begin_ip, end_ip, network_name)
    network_spec = {
        'name': network_name,
        'ipBlocks': [{'beginIp': begin_ip, 'endIp': end_ip}]
    }
    resp = oms_ctl.increase_ips(network_spec)
    if resp.status_code != 200:
        raise ProvisionError('Failed to add %s-%s to network %s.',
                             begin_ip, end_ip, network_name)


def upgrade(oms_ctl, blue_name, green_name, spec):
    LOG.info('Start to upgrade VIO cluster %s.', blue_name)
    # Create green cluster
    LOG.info('Create green cluster %s', green_name)
    oms_ctl.upgrade_provision(blue_name, spec)
    # Migrate data
    LOG.info('Migrate data from cluster: %s', blue_name)
    oms_ctl.upgrade_migrate_data(blue_name)
    # Switch to green cluster
    LOG.info('Switch from cluster: %s', blue_name)
    oms_ctl.upgrade_switch_to_green(blue_name)
    if not check_cluster_status(oms_ctl, green_name, ['RUNNING']):
        raise ProvisionError('Upgrading VIO cluster failed.')
    LOG.info('Successfully upgraded VIO cluster %s.', blue_name)


def get_compute_cluster_moids(cluster_spec):
    compute_group = get_nodegroup_by_role(cluster_spec, 'Compute')
    instances = compute_group['instances']
    moids = list()
    for instance in instances:
        moids.append(instance['attributes']['cluster_moid'])
    return moids
