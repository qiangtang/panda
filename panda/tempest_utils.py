import logging
import os
import ConfigParser
import time

from novaclient import client as nova_client
from cinderclient import client as cinder_client
from neutronclient.neutron import client as neutron_client
from keystoneclient.v3 import client as keystone_client
from glanceclient import Client as GlanceClient
import yaml

import shellutil as shell
from exceptions import NotSupportedError
from exceptions import NotFoundError
from cluster_utils import NSXV3_BACKEND
from cluster_utils import NSXV_BACKEND
import task_utils
from os_utils import get_keystone_client
from os_utils import get_session
from os_utils import create_if_not_exist
from os_utils import grant_role_on_project
from os_utils import get_auth_url
from os_utils import get_auth_url2
from os_utils import DEFAULT_DOMAIN_ID

LOG = logging.getLogger(__name__)
TEMPEST_DIR = 'tempest'
NEUTRON_FWAAS_DIR = 'neutron-fwaas'
HEAT_DIR = 'heat-tempest-plugin'
PACKAGE_MAP = {'nova': 'tempest.api.compute',
               'cinder': 'tempest.api.volume',
               'neutron': 'tempest.api.network',
               # 'heat': 'tempest.api.orchestration',
               # 'heat': 'heat_integrationtests',
               'heat': 'heat_tempest_plugin',
               'keystone': 'tempest.api.identity',
               'glance': 'tempest.api.image',
               'scenario': 'tempest.scenario',
               'nsxv': 'vmware_nsx_tempest.tests.nsxv.',
               'nsxv3': 'vmware_nsx_tempest.tests.nsxv3',
               'dvs': 'vmware_nsx_tempest.tests.dvs',
               'fwaas': 'neutron_fwaas.tests.tempest_plugin'}
LEGACY_PROVIDER = 'legacy'
DYNAMIC_PROVIDER = 'dynamic'
PRE_PROVISIONED_PROVIDER = 'pre-provisioned'
ROLE_NAME = 'member-tempest'
STORAGE_ROLE_NAME = 'storage-ops-tempest'
IMAGE_NAME = 'ubuntu-14.04-server-amd64'
IMAGE_NAME_4_1 = 'ubuntu-16.04-server-cloudimg-amd64'
FLAVOR1_NAME = 'm1-tempest'
FLAVOR2_NAME = 'm2-tempest'
DATA_NET_NAME = 'flat-tempest'
DATA_NET_CIDR = '172.16.10.0/24'
EXT_NET_NAME = 'public-tempest'
ROUTER_NAME = 'router-tempest'
TENANT_NAME = 'default-tenant-tempest'
ALT_TENANT_NAME = 'alt-tenant-tempest'
GIT_CLONE = 'GIT_SSL_NO_VERIFY=true git clone'
SMOKE_SUFFIX = '-smoke'


def get_data_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def install_fwaas_tempest(protocol, fwaas_repo, fwaas_branch):
    # Get fwaas plugin
    if os.path.exists(NEUTRON_FWAAS_DIR):
        LOG.info('neutron-fwaas already exists, skip cloning.')
    else:
        LOG.info('Clone neutron-fwaas from repository.')
        clone_url = '%s://%s' % (protocol, fwaas_repo)
        task_utils.safe_run('%s -b %s %s' % (GIT_CLONE, fwaas_branch,
                                             clone_url),
                            'Clone neutron-fwaas')

    # To do: testscenarios is not installed, which is needed for fwaas
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install ' \
          'testscenarios' % TEMPEST_DIR
    task_utils.safe_run(cmd, 'install testscenarios')
    LOG.info('Install neutron-fwaas.')
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install -e %s' % \
          (TEMPEST_DIR, NEUTRON_FWAAS_DIR)
    task_utils.safe_run(cmd, 'install neutron-fwaas')


def install_heat(protocol, heat_repo, heat_branch):
    if os.path.exists(HEAT_DIR):
        LOG.info('Heat already exists, skip cloning.')
    else:
        LOG.info('Clone heat from repository.')
        clone_url = '%s://%s' % (protocol, heat_repo)
        task_utils.safe_run('%s -b %s %s' % (GIT_CLONE, heat_branch,
                                             clone_url),
                            'Clone heat')
    LOG.info('Install %s.' % HEAT_DIR)
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install -e %s' % \
          (TEMPEST_DIR, HEAT_DIR)
    task_utils.safe_run(cmd, 'install heat')
    # ./tempest/tools/with_venv.sh pip install -r heat/test-requirements.txt
    cmd = './%s/tools/with_venv.sh pip install -r %s/test-requirements.txt' % \
          (TEMPEST_DIR, HEAT_DIR)
    task_utils.safe_run(cmd, 'install heat requirements')


def install_tempest(repository='github.com/openstack/tempest.git',
                    branch='18.0.0',
                    enable_nsx=True,
                    nsx_repo='git.openstack.org/openstack/'
                             'vmware-nsx-tempest-plugin',
                    nsx_branch='master',
                    enable_fwaas=True,
                    fwaas_repo='github.com/openstack/neutron-fwaas',
                    fwaas_branch='master',
                    enable_heat=True,
                    # heat_repo='p3-review.eng.vmware.com/heat',
                    heat_repo='github.com/openstack/heat-tempest-plugin.git',
                    heat_branch='master',
                    protocol='http',
                    conf_template=None):
    if os.path.exists(TEMPEST_DIR):
        LOG.info('Tempest already exists, skip cloning.')
    else:
        LOG.info('Clone tempest from repository.')
        clone_url = '%s://%s' % (protocol, repository)
        task_utils.safe_run('%s -b %s %s' % (GIT_CLONE, branch, clone_url),
                            'Clone tempest')
        try:
            # apply patch due to bug 2088762
            git_pick = 'GIT_SSL_NO_VERIFY=true git fetch ' \
                       'http://git.openstack.org/openstack/tempest ' \
                       'refs/changes/57/557657/4 && git cherry-pick FETCH_HEAD'
            with shell.cd(TEMPEST_DIR):
                shell.local(git_pick)
        except Exception:
            LOG.debug('Cherry-pick tempest failed. %s' % git_pick)
    with shell.cd(TEMPEST_DIR):
        # shell.local("sed -i 's/-500/-1500/g' .testr.conf")
        LOG.info('Copy template to etc/tempest.conf')
        conf_template = conf_template or os.path.join(get_data_path(),
                                                      'tempest.conf.template')
        shell.local('cp %s etc/tempest.conf' % conf_template,
                    raise_error=True)
        shell.local('virtualenv .venv')
    LOG.info('Install tempest.')
    # TODO: a workaround to fix cmd2 version error
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install ' \
          'cmd2==0.8.7' % TEMPEST_DIR
    task_utils.safe_run(cmd, 'install cmd2')
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install %s' % \
          (TEMPEST_DIR, TEMPEST_DIR)
    task_utils.safe_run(cmd, 'install tempest')
    # TODO: a workaround to fix the tempest dependency error.
    cmd = './%s/tools/with_venv.sh pip --no-cache-dir install ' \
          'babel' % TEMPEST_DIR
    task_utils.safe_run(cmd, 'install babel')
    if enable_fwaas:
        install_fwaas_tempest(protocol, fwaas_repo, fwaas_branch)
    if enable_heat:
        install_heat(protocol, heat_repo, heat_branch)
    LOG.info('Tempest has been successfully installed.')


def convert_unicode_to_string(string):
    if isinstance(string, unicode):
        return string.encode('ascii')
    else:
        return string


def add_account(user_name, password, tenant_name, tenant_id, roles=None,
                network=None, router=None):
    # tenant id is retrieved from return value of keystoneclient and it is
    # unicode. Unicode tag is added When you dump it to a yaml file:
    # tenant_id: !!python/unicode '8418fb2bd1e64108906f1f623aaf2239'
    # Current tempest lib can not parse yaml file with unicode tag.
    tenant_id = convert_unicode_to_string(tenant_id)
    tenant_name = convert_unicode_to_string(tenant_name)
    account = {
        'username': user_name,
        'password': password,
        'tenant_name': tenant_name,
        'tenant_id': tenant_id
    }
    if roles:
        account['roles'] = roles
    if network or router:
        account['resources'] = []
        if network:
            account['resources'].append(network)
        if router:
            account['resources'].append(router)
    return account


def config_identity(config_parser, p_vip, admin_user_name, admin_pwd,
                    admin_tenant_name, creds_provider, default_user_name=None,
                    default_pwd=None, alt_user_name=None, alt_pwd=None):
    uri_v3 = get_auth_url(p_vip, 'v3')
    uri_v2 = get_auth_url(p_vip)
    keystone = get_keystone_client(p_vip=p_vip,
                                   username=admin_user_name,
                                   password=admin_pwd,
                                   project_name=admin_tenant_name,
                                   domain_name=DEFAULT_DOMAIN_ID)
    config_parser.set('identity', 'uri_v3', uri_v3)
    config_parser.set('identity', 'uri', uri_v2)
    config_parser.set('identity', 'auth_version', 'v3')
    config_parser.set('auth', 'admin_project_name', admin_tenant_name)
    config_parser.set('auth', 'admin_password', admin_pwd)
    config_parser.set('auth', 'admin_username', admin_user_name)
    # config heat_plugin
    auth_url = get_auth_url2(p_vip, 'v3')
    config_parser.set('heat_plugin', 'auth_url', auth_url)
    config_parser.set('heat_plugin', 'auth_version', '3')
    config_parser.set('heat_plugin', 'admin_username', admin_user_name)
    config_parser.set('heat_plugin', 'admin_password', admin_pwd)
    # Create tempest test role
    test_role = create_if_not_exist(keystone.roles, 'role', ROLE_NAME)
    config_parser.set('auth', 'tempest_roles', ROLE_NAME)
    # Both SQL backend and LDAP backend is Default
    config_parser.set('auth', 'admin_domain_name', 'Default')
    default_domain = keystone.domains.get(DEFAULT_DOMAIN_ID)
    default_tenant = create_if_not_exist(keystone.projects, 'project',
                                         TENANT_NAME,
                                         domain=default_domain)
    # config_parser.set('heat_plugin', 'username', 'admin')
    # config_parser.set('heat_plugin', 'password', 'vmware')
    # config_parser.set('heat_plugin', 'project_name', 'admin')
    # config_parser.set('heat_plugin', 'user_domain_name', 'Default')
    # config_parser.set('heat_plugin', 'project_domain_name', 'Default')
    try:
        heat_user = create_if_not_exist(keystone.users, 'user', 'demo',
                                        password='vmware',
                                        default_project=default_tenant)
        grant_role_on_project(keystone, default_tenant, heat_user, test_role)
        config_parser.set('heat_plugin', 'username', 'admin')
        config_parser.set('heat_plugin', 'password', 'vmware')
        config_parser.set('heat_plugin', 'project_name', 'admin')
        config_parser.set('heat_plugin', 'user_domain_name', 'Default')
        config_parser.set('heat_plugin', 'project_domain_name', 'Default')
    except Exception:
        config_parser.set('heat_plugin', 'username', 'admin')
        config_parser.set('heat_plugin', 'password', 'vmware')
        config_parser.set('heat_plugin', 'project_name', 'admin')
        config_parser.set('heat_plugin', 'user_domain_name', 'local')
        config_parser.set('heat_plugin', 'project_domain_name', 'local')
    if creds_provider in [LEGACY_PROVIDER, PRE_PROVISIONED_PROVIDER]:
        # Create default tenant and user
        default_domain = keystone.domains.get(DEFAULT_DOMAIN_ID)
        default_tenant = create_if_not_exist(keystone.projects, 'project',
                                             TENANT_NAME,
                                             domain=default_domain)
        default_user = create_if_not_exist(keystone.users, 'user',
                                           default_user_name,
                                           password=default_pwd,
                                           tenant_id=default_tenant.id)

        grant_role_on_project(keystone, default_tenant, default_user,
                              test_role)
        # Create alter tenant and user
        alt_tenant = create_if_not_exist(keystone.projects, 'project',
                                         ALT_TENANT_NAME,
                                         domain=default_domain)
        alt_user = create_if_not_exist(keystone.users, 'user', alt_user_name,
                                       password=alt_pwd,
                                       tenant_id=alt_tenant.id)

        grant_role_on_project(keystone, alt_tenant, alt_user, test_role)
        if LEGACY_PROVIDER == creds_provider:
            # Legacy provider can only be used before Newton release.
            config_parser.set('identity', 'tenant_name', TENANT_NAME)
            config_parser.set('identity', 'username', default_user_name)
            config_parser.set('identity', 'password', default_pwd)
            config_parser.set('identity', 'alt_tenant_name', ALT_TENANT_NAME)
            config_parser.set('identity', 'alt_username', alt_user_name)
            config_parser.set('identity', 'alt_password', alt_pwd)
        elif PRE_PROVISIONED_PROVIDER == creds_provider:
            accounts = list()
            accounts.append(add_account(default_user_name, default_pwd,
                                        TENANT_NAME, default_tenant.id,
                                        roles=[ROLE_NAME]))
            accounts.append(add_account(alt_user_name, alt_pwd,
                                        ALT_TENANT_NAME, alt_tenant.id,
                                        roles=[ROLE_NAME]))
            project_id = None
            for project in keystone.projects.list():
                if project.name == admin_tenant_name \
                        and project.domain_id == DEFAULT_DOMAIN_ID:
                    project_id = project.id
                    break
            if not project_id:
                raise NotFoundError('Project %s not found' % admin_tenant_name)
            accounts.append(add_account(admin_user_name, admin_pwd,
                                        admin_tenant_name, project_id,
                                        roles=['admin']))
            test_accounts_file = os.path.join(os.getcwd(), TEMPEST_DIR,
                                              'etc/accounts.yaml')
            with open(test_accounts_file, 'w') as fh:
                yaml.dump(accounts, fh, default_flow_style=False,
                          default_style=False, indent=2, encoding='utf-8',
                          allow_unicode=True)
            config_parser.set('auth', 'test_accounts_file', test_accounts_file)
        config_parser.set('auth', 'use_dynamic_credentials', 'false')
        config_parser.set('auth', 'create_isolated_networks', 'false')
    elif creds_provider == DYNAMIC_PROVIDER:
        config_parser.set('auth', 'use_dynamic_credentials', 'true')
        config_parser.set('auth', 'create_isolated_networks', 'false')
    else:
        raise NotSupportedError('Not support %s' % creds_provider)
    # Create role for object storage
    create_if_not_exist(keystone.roles, 'role', STORAGE_ROLE_NAME)
    config_parser.set('object-storage', 'operator_role', STORAGE_ROLE_NAME)


def config_compute(config_parser, p_vip, user_name, password,
                   tenant_name, min_compute_nodes):
    session = get_session(p_vip=p_vip,
                          username=user_name,
                          password=password,
                          project_name=tenant_name,
                          domain_name=DEFAULT_DOMAIN_ID)
    nova = nova_client.Client('2', session=session)
    # Create the flavors
    m1 = create_if_not_exist(nova.flavors, 'flavor', FLAVOR1_NAME, ram=512,
                             vcpus=1, disk=15, is_public=True)
    config_parser.set('compute', 'flavor_ref', m1.id)
    config_parser.set('orchestration', 'instance_type', FLAVOR1_NAME)
    config_parser.set('heat_plugin', 'instance_type', FLAVOR1_NAME)
    m2 = create_if_not_exist(nova.flavors, 'flavor', FLAVOR2_NAME, ram=1024,
                             vcpus=2, disk=15, is_public=True)
    config_parser.set('compute', 'flavor_ref_alt', m2.id)
    config_parser.set('compute', 'min_compute_nodes', min_compute_nodes)
    config_parser.set('heat_plugin', 'minimal_instance_type', FLAVOR2_NAME)
    config_parser.set('compute-feature-enabled', 'pause', 'false')


def config_image(config_parser, p_vip, user_name, password, tenant_name):
    # Get the default image.
    session = get_session(p_vip=p_vip,
                          username=user_name,
                          password=password,
                          project_name=tenant_name,
                          domain_name=DEFAULT_DOMAIN_ID)
    glance = GlanceClient(version='2', session=session)
    count = 0
    default_image = None
    alt_image = None
    for image in glance.images.list():
        count += 1
        if image.name == IMAGE_NAME_4_1:
            default_image = image
        else:
            alt_image = image
    if count == 0:
        raise NotSupportedError('At least 1 image in glance is required.')
    default_image = default_image or alt_image
    LOG.info('Use image %s as default image in tempest', default_image.name)
    alt_image = alt_image or default_image
    LOG.info('Use image %s as alter image in tempest', alt_image.name)
    config_parser.set('compute', 'image_ref', default_image.id)
    config_parser.set('compute', 'image_ref_alt', alt_image.id)
    config_parser.set('heat_plugin', 'image_ref', default_image.id)
    config_parser.set('heat_plugin', 'minimal_image_ref', default_image.id)


def get_network(neutron, net_name):
    nets = neutron.list_networks()['networks']
    for net in nets:
        if net['name'] == net_name:
            return net


def config_network(config_parser, p_vip, user_name, password,
                   neutron_backend, tenant_name,
                   tenant_net_cidr, ext_net_cidr=None,
                   ext_net_start_ip=None, ext_net_end_ip=None,
                   ext_net_gateway=None, vlan_transparent=False):
    session = get_session(p_vip=p_vip,
                          username=user_name,
                          password=password,
                          project_name=tenant_name,
                          domain_name=DEFAULT_DOMAIN_ID)
    neutron = neutron_client.Client('2.0', session=session)
    data_network = get_network(neutron, DATA_NET_NAME)
    if not data_network:
        # Create fixed network
        if neutron_backend in [NSXV_BACKEND, NSXV3_BACKEND]:
            net_spec = {
                "network":
                    {
                        "name": DATA_NET_NAME,
                        "admin_state_up": True,
                        "shared": True
                    }
            }
            if vlan_transparent:
                net_spec["network"]["vlan_transparent"] = vlan_transparent
        else:
            net_spec = {
                "network":
                    {
                        "provider:network_type": "flat",
                        "name": DATA_NET_NAME,
                        "provider:physical_network": "dvs",
                        "admin_state_up": True,
                        "shared": True
                    }
            }
        LOG.info("Create data network %s.", DATA_NET_NAME)
        data_network = neutron.create_network(net_spec)['network']
        # Create data subnet
        # TODO: Create a static subnet as fixed network while using dynamic
        # credentials.
        subnet_spec = {
            'subnet':
                {
                    "name": DATA_NET_NAME,
                    'network_id': data_network['id'],
                    'cidr': tenant_net_cidr,
                    'ip_version': 4,
                    'enable_dhcp': True
                }
        }
        LOG.info("Create %s subnet.", DATA_NET_NAME)
        data_subnet = neutron.create_subnet(subnet_spec)['subnet']
        data_network['subnets'] = [data_subnet['id']]
    else:
        LOG.info("Found data network %s", DATA_NET_NAME)
    config_parser.set('compute', 'fixed_network_name', DATA_NET_NAME)
    config_parser.set('heat_plugin', 'fixed_network_name', DATA_NET_NAME)
    config_parser.set('heat_plugin', 'fixed_subnet_name', DATA_NET_NAME)
    if neutron_backend in [NSXV_BACKEND, NSXV3_BACKEND]:
        ext_network = get_network(neutron, EXT_NET_NAME)
        if not ext_network:
            # Create external network
            net_spec = {
                "network":
                    {
                        "router:external": "True",
                        "name": EXT_NET_NAME,
                        "admin_state_up": True
                    }
            }
            LOG.info("Create external network %s.", EXT_NET_NAME)
            ext_network = neutron.create_network(net_spec)['network']
            # Create external subnet
            subnet_spec = {
                'subnet':
                    {
                        "name": EXT_NET_NAME,
                        'network_id': ext_network['id'],
                        'cidr': ext_net_cidr,
                        'ip_version': 4,
                        'enable_dhcp': False,
                        'gateway_ip': ext_net_gateway,
                        'allocation_pools': [{"start": ext_net_start_ip,
                                              "end": ext_net_end_ip}]
                    }
            }
            LOG.info("Create %s subnet.", EXT_NET_NAME)
            neutron.create_subnet(subnet_spec)
            LOG.info("Create router %s.", ROUTER_NAME)
            router_spec = {
                'router':
                    {
                        'name': ROUTER_NAME,
                        'external_gateway_info':
                            {
                                'network_id': ext_network['id']
                            }
                    }
            }
            router = neutron.create_router(router_spec)['router']
            LOG.info("Add %s to router %s", DATA_NET_NAME, ROUTER_NAME)
            add_router_interface_spec = {
                'subnet_id': data_network['subnets'][0]
            }
            neutron.add_interface_router(router['id'],
                                         add_router_interface_spec)
        else:
            LOG.info("Found external network %s", EXT_NET_NAME)
        config_parser.set('network', 'public_network_id', ext_network['id'])
        config_parser.set('network-feature-enabled', 'api_extensions',
                          'binding, dist-router, multi-provider, provider, '
                          'quotas,external-net, extraroute, router, '
                          'security-group, port-security')
        config_parser.set('network-feature-enabled',
                          'port_admin_state_change', 'False')
        config_parser.set('network-feature-enabled', 'ipv6', 'False')
        config_parser.set('network-feature-enabled', 'port_security', 'True')
        config_parser.set('network', 'floating_network_name', EXT_NET_NAME)
        config_parser.set('heat_plugin', 'floating_network_name', EXT_NET_NAME)
        # Since we can't figure out the way to access floatingip from jumphost
        # now, we disable validation in nsxv3 driver.
        # TODO: enable once the validation works.
        if NSXV_BACKEND == neutron_backend:
            config_parser.set('validation', 'run_validation', 'true')
            config_parser.set('validation', 'connect_method', 'floating')
    else:
        config_parser.set('network', 'project_network_cidr', tenant_net_cidr)
        config_parser.set('network', 'project_network_mask_bits', '24')
        config_parser.set('validation', 'run_validation', 'false')


def config_volume(config_parser, p_vip, user_name, password,
                  tenant_name):
    session = get_session(p_vip=p_vip,
                          username=user_name,
                          password=password,
                          project_name=tenant_name,
                          domain_name=DEFAULT_DOMAIN_ID)
    nova = nova_client.Client('2', session=session)
    # Get Nova API versions
    versions = nova.versions.list()
    if (len(versions) == 1 and
            versions[0].to_dict().get('status') == 'SUPPORTED'):
        config_parser.set('volume', 'storage_protocol', 'LSI Logic SCSI')
    # Enlarge volume quota for admin
    LOG.debug('Enlarge volume and snapshot quotas of admin.')
    keystone = keystone_client.Client(session=session)
    tenant_id = None
    for project in keystone.projects.list():
        if project.name == 'admin' and project.domain_id == 'default':
            tenant_id = project.id
            break
    if tenant_id:
        cinder = cinder_client.Client('3', session=session)
        cinder.quotas.update(tenant_id, volumes=100)
        cinder.quotas.update(tenant_id, snapshots=100)


def config_nsx(config_parser, neutron_backend, nsx_manager, nsx_user, nsx_pwd):
    if NSXV_BACKEND == neutron_backend:
        if not config_parser.has_section('nsxv'):
            config_parser.add_section('nsxv')
        config_parser.set('nsxv', 'manager_uri', 'http://%s' % nsx_manager)
        config_parser.set('nsxv', 'user', nsx_user)
        config_parser.set('nsxv', 'password', nsx_pwd)
    else:
        if not config_parser.has_section('nsxv3'):
            config_parser.add_section('nsxv3')
        config_parser.set('nsxv3', 'nsx_manager', nsx_manager)
        config_parser.set('nsxv3', 'nsx_user', nsx_user)
        config_parser.set('nsxv3', 'nsx_password', nsx_pwd)
    # Below are configurations for NSX plugin
    config_parser.set('network', 'dns_search_domain', 'vmware.com')
    config_parser.set('network', 'host_in_search_domain', 'mail')
    # Not sure why not default setting.
    config_parser.set('validation', 'ssh_shell_prologue', '')
    # NSX test use user/password for authentication
    config_parser.set('validation', 'image_ssh_user', 'ubuntu')


def config_tempest(p_vip, admin_user, admin_pwd, neutron_backend,
                   creds_provider, default_user=None, default_pwd=None,
                   alter_user=None, alter_pwd=None, ext_net_cidr=None,
                   ext_net_start_ip=None, ext_net_end_ip=None,
                   ext_net_gateway=None, tempest_log_file=None,
                   admin_tenant='admin', min_compute_nodes=1, nsx_manager=None,
                   nsx_user=None, nsx_pwd=None, tenant_net_cidr=None,
                   vlan_transparent=False):
    config_parser = ConfigParser.ConfigParser()
    conf_path = '%s/etc/tempest.conf' % TEMPEST_DIR
    config_parser.read(conf_path)
    config_identity(config_parser, p_vip, admin_user, admin_pwd,
                    admin_tenant, creds_provider, default_user, default_pwd,
                    alter_user, alter_pwd)
    config_compute(config_parser, p_vip, admin_user, admin_pwd,
                   admin_tenant, min_compute_nodes)
    config_image(config_parser, p_vip, admin_user, admin_pwd,
                 admin_tenant)
    config_network(config_parser, p_vip, admin_user, admin_pwd,
                   neutron_backend, admin_tenant, tenant_net_cidr,
                   ext_net_cidr, ext_net_start_ip, ext_net_end_ip,
                   ext_net_gateway, vlan_transparent)
    config_volume(config_parser, p_vip, admin_user, admin_pwd,
                  admin_tenant)
    if tempest_log_file:
        config_parser.set('DEFAULT', 'log_file', tempest_log_file)
    # Configure darshboard
    config_parser.set('dashboard', 'login_url',
                      'http://%s/auth/login' % p_vip)
    config_parser.set('dashboard', 'dashboard_url', 'http://%s/' % p_vip)
    LOG.info('Update configurations to %s' % conf_path)
    config_parser.write(open(conf_path, 'w'))
    if neutron_backend in [NSXV3_BACKEND, NSXV_BACKEND]:
        config_nsx(config_parser, neutron_backend,
                   nsx_manager, nsx_user, nsx_pwd)
        nsx_conf_path = '%s/etc/tempest.conf.nsx' % TEMPEST_DIR
        LOG.info('Generate nsx configurations to %s' % nsx_conf_path)
        config_parser.write(open(nsx_conf_path, 'w'))


def split_name_and_id(line):
    index = line.find('[')
    if index > 0:
        return line[0:index], line[index:]
    else:
        return line, ''


def strip_id(line):
    line = line.replace('\n', '').strip()
    index = line.find('[')
    if index > 0:
        return line[0:index]
    else:
        return line


def write_suite_file(name, test_list):
    LOG.info('Write test suite %s.txt, '
             'total cases %s' % (name, len(test_list)))
    with open('%s/%s.txt' % (TEMPEST_DIR, name), 'w') as f:
        for test in test_list:
            f.write(test)
            f.write('\n')


def generate_run_list(neutron_backend):
    with shell.cd(TEMPEST_DIR):
        if not os.path.exists('%s/.stestr' % TEMPEST_DIR):
            shell.local('./tools/with_venv.sh stestr init', raise_error=True)
        lines = shell.local('./tools/with_venv.sh stestr list',
                            raise_error=True)[1]
    # Obtain all tests into a dict {test_name: test_id}
    all_tests = dict([split_name_and_id(line) for line in lines.split('\n')
                      if line.startswith('tempest.') or
                      line.startswith('vmware_nsx_tempest.') or
                      line.startswith('neutron_fwaas.') or
                      line.startswith('heat_tempest_plugin.')])

    # Get excluded tests into a list [test_name]
    exclude_file = '%s/%s-excluded-tests.txt' % (get_data_path(),
                                                 neutron_backend)
    if os.path.exists(exclude_file):
        LOG.debug('Found %s, tests in it will be excluded.', exclude_file)
        excluded_tests = [strip_id(line) for line in open(exclude_file)
                          if (line.strip() != '') and
                          (not line.strip().startswith('#'))]
    else:
        excluded_tests = []
        LOG.debug('Excluded list not found, all tests will be included')
    # Get all tests minus excluded tests [test_name + test_id]
    exec_tests = [test_name + test_id for (test_name, test_id)
                  in all_tests.items() if test_name not in excluded_tests]

    # Get test case and exclude metrics
    num_all_tests = len(all_tests)
    num_excluded = len(excluded_tests)
    num_tests = len(exec_tests)

    LOG.debug('Total number of available tests: %s' % num_all_tests)
    LOG.debug('Total number of excluded tests: %s' % num_excluded)
    LOG.debug('Total number of tests to run: %s' % num_tests)

    outdated_tests = []
    if num_tests != num_all_tests - num_excluded:
        all_tests_list = all_tests.keys()
        outdated_tests = [test_name for test_name in excluded_tests
                          if test_name not in all_tests_list]
    if outdated_tests:
        LOG.debug('Below tests in exclude-tests.txt are outdated.')
        for test in outdated_tests:
            LOG.debug(test)

    write_suite_file('included-tests', exec_tests)
    test_list = [test_name + test_id for (test_name, test_id)
                 in all_tests.items()]
    write_suite_file('all-tests', test_list)
    for key in PACKAGE_MAP:
        test_list = [test for test in exec_tests
                     if test.startswith(PACKAGE_MAP[key])]
        smoke_test_list = [test for test in test_list if 'smoke' in test]
        write_suite_file(key, test_list)
        write_suite_file(key + SMOKE_SUFFIX, smoke_test_list)
    # uninstall vmware_nsx_tempest temporarily
    # shell.local("./%s/tools/with_venv.sh pip --no-cache-dir uninstall"
    #             " vmware-nsx-tempest-plugin --yes" % TEMPEST_DIR)
    # remove breaking files since pip uninstall fails
    shell.local("rm ./vmware-nsx-tempest-plugin/vmware_nsx_tempest/tests/"
                "api/test_v2_fwaas.py")
    shell.local("rm ./vmware-nsx-tempest-plugin/vmware_nsx_tempest/tests/"
                "scenario/test_qos.py")
    shell.local("rm ./vmware-nsx-tempest-plugin/vmware_nsx_tempest/tests/"
                "api/test_vpn.py")


def make_reports(report_dir, suite_name):
    subunit = '/tmp/%s-subunit.txt' % suite_name
    junit_xml = os.path.join(report_dir, '%s_results.xml' % suite_name)
    shell.local('./tools/with_venv.sh stestr last --subunit > %s' % subunit)
    shell.local('subunit2junitxml --output-to=%s < %s' % (junit_xml, subunit))
    html_report_file = os.path.join(report_dir, '%s_results.html' % suite_name)
    try:
        shell.local('subunit2html %s %s' % (subunit, html_report_file),
                    raise_error=True)
        LOG.info('Generated report to %s.' % html_report_file)
    except Exception:
        LOG.exception('Failed to generate report to %s.' % html_report_file)


def run_test(component, report_dir, smoke=False, parallel=False,
             rerun_failed=False):
    testr_opts = ''
    env_vars = ''
    if parallel:
        testr_opts += '--parallel'
    if not os.path.isabs(report_dir):
        report_dir = os.path.abspath(report_dir)
    if component.startswith('nsx'):
        env_vars = 'export TEMPEST_CONFIG=tempest.conf.nsx;'
    # if component.startswith('dvs') or component.startswith('nsx'):
    #     # install vmware_nsx_tempest when run into its case
    #     shell.local("./%s/tools/with_venv.sh pip --no-cache-dir install -e"
    #                 " vmware-nsx-tempest-plugin" % TEMPEST_DIR)
    if smoke:
        component += SMOKE_SUFFIX
    with shell.cd(TEMPEST_DIR):
        LOG.info('Start to run %s tests' % component)
        start = time.time()
        cmd = "%s ./tools/with_venv.sh stestr run %s --subunit " \
              "--load-list=%s.txt | subunit2pyunit" % \
              (env_vars, testr_opts, component)
        if component == 'scenario':
            cmd = "%s ./tools/with_venv.sh stestr run %s --subunit " \
                  "--serial --load-list=%s.txt | subunit2pyunit" % \
                  (env_vars, testr_opts, component)
        shell.local(cmd)
        end = time.time()
        LOG.info('%s tests took %s seconds', component, (end - start))
        make_reports(report_dir, component)
        failed_tests = shell.local('./tools/with_venv.sh stestr failing '
                                   '--subunit | subunit-ls')[1]
        if failed_tests.strip():
            LOG.info('Failed tests:\n%s', failed_tests)
            if rerun_failed:
                LOG.info('Rerun above failed tests.')
                start = time.time()
                cmd = '%s ./tools/with_venv.sh stestr run --failing ' \
                      '--subunit | subunit2pyunit' % env_vars
                if component == 'scenario':
                    cmd = '%s ./tools/with_venv.sh stestr run --failing ' \
                          '--serial --subunit | subunit2pyunit' % env_vars
                shell.local(cmd)
                end = time.time()
                LOG.info('Rerun %s failed tests took %s seconds', component,
                         (end - start))
                make_reports(report_dir, '%s_rerun' % component)
