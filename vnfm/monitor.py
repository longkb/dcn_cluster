# Copyright 2015 Intel Corporation.
# All Rights Reserved.
#
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import inspect
import threading
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six

from tacker.common import clients
from tacker.common import driver_manager
from tacker import context as t_context
from tacker import manager
from tacker.db.common_services import common_services_db
from tacker.plugins.common import constants
from tacker.vnfm.infra_drivers.openstack import openstack
from tacker.vnfm import vim_client

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
OPTS = [
    cfg.IntOpt('check_intvl',
               default=10,
               help=_("check interval for monitor")),
]
CONF.register_opts(OPTS, group='monitor')


def config_opts():
    return [('monitor', OPTS),
            ('tacker', VNFMonitor.OPTS),
            ('tacker', VNFAlarmMonitor.OPTS), ]


def _log_monitor_events(context, vnf_dict, evt_details):
    _cos_db_plg = common_services_db.CommonServicesPluginDb()
    _cos_db_plg.create_event(context, res_id=vnf_dict['id'],
                             res_type=constants.RES_TYPE_VNF,
                             res_state=vnf_dict['status'],
                             evt_type=constants.RES_EVT_MONITOR,
                             tstamp=timeutils.utcnow(),
                             details=evt_details)


class VNFMonitor(object):
    """VNF Monitor."""

    _instance = None
    _hosting_vnfs = dict()   # vnf_id => dict of parameters
    _status_check_intvl = 0
    _lock = threading.RLock()

    OPTS = [
        cfg.ListOpt(
            'monitor_driver', default=['ping', 'http_ping'],
            help=_('Monitor driver to communicate with '
                   'Hosting VNF/logical service '
                   'instance tacker plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'tacker')

    def __new__(cls, boot_wait, check_intvl=None):
        if not cls._instance:
            cls._instance = super(VNFMonitor, cls).__new__(cls)
        return cls._instance

    def __init__(self, boot_wait, check_intvl=None):
        self._monitor_manager = driver_manager.DriverManager(
            'tacker.tacker.monitor.drivers',
            cfg.CONF.tacker.monitor_driver)

        self.boot_wait = boot_wait
        if check_intvl is None:
            check_intvl = cfg.CONF.monitor.check_intvl
        self._status_check_intvl = check_intvl
        LOG.debug('Spawning VNF monitor thread')
        threading.Thread(target=self.__run__).start()

    def __run__(self):
        while(1):
            time.sleep(self._status_check_intvl)

            with self._lock:
                for hosting_vnf in self._hosting_vnfs.values():
                    if hosting_vnf.get('dead', False):
                        LOG.debug('monitor skips dead vnf %s', hosting_vnf)
                        continue

                    self.run_monitor(hosting_vnf)

    @staticmethod
    def to_hosting_vnf(vnf_dict, action_cb):
        return {
            'id': vnf_dict['id'],
            'management_ip_addresses': jsonutils.loads(
                vnf_dict['mgmt_url']),
            'action_cb': action_cb,
            'vnf': vnf_dict,
            'monitoring_policy': jsonutils.loads(
                vnf_dict['attributes']['monitoring_policy'])
        }

    def add_hosting_vnf(self, new_vnf):
        LOG.debug('Adding host %(id)s, Mgmt IP %(ips)s',
                  {'id': new_vnf['id'],
                   'ips': new_vnf['management_ip_addresses']})
        new_vnf['boot_at'] = timeutils.utcnow()
        with self._lock:
            self._hosting_vnfs[new_vnf['id']] = new_vnf

        attrib_dict = new_vnf['vnf']['attributes']
        mon_policy_dict = attrib_dict['monitoring_policy']
        evt_details = (("VNF added for monitoring. "
                        "mon_policy_dict = %s,") % (mon_policy_dict))
        _log_monitor_events(t_context.get_admin_context(), new_vnf['vnf'],
                            evt_details)

    def delete_hosting_vnf(self, vnf_id):
        LOG.debug('deleting vnf_id %(vnf_id)s', {'vnf_id': vnf_id})
        with self._lock:
            hosting_vnf = self._hosting_vnfs.pop(vnf_id, None)
            if hosting_vnf:
                LOG.debug('deleting vnf_id %(vnf_id)s, Mgmt IP %(ips)s',
                          {'vnf_id': vnf_id,
                           'ips': hosting_vnf['management_ip_addresses']})

    def run_monitor(self, hosting_vnf):
        mgmt_ips = hosting_vnf['management_ip_addresses']
        vdupolicies = hosting_vnf['monitoring_policy']['vdus']

        vnf_delay = hosting_vnf['monitoring_policy'].get(
            'monitoring_delay', self.boot_wait)

        for vdu in vdupolicies.keys():
            if hosting_vnf.get('dead'):
                return

            policy = vdupolicies[vdu]
            for driver in policy.keys():
                params = policy[driver].get('monitoring_params', {})

                vdu_delay = params.get('monitoring_delay', vnf_delay)

                if not timeutils.is_older_than(
                    hosting_vnf['boot_at'],
                        vdu_delay):
                        continue

                actions = policy[driver].get('actions', {})
                if 'mgmt_ip' not in params:
                    params['mgmt_ip'] = mgmt_ips[vdu]

                driver_return = self.monitor_call(driver,
                                                  hosting_vnf['vnf'],
                                                  params)

                LOG.debug('driver_return %s', driver_return)

                if driver_return in actions:
                    action = actions[driver_return]
                    hosting_vnf['action_cb'](action)

    def mark_dead(self, vnf_id):
        self._hosting_vnfs[vnf_id]['dead'] = True

    def _invoke(self, driver, **kwargs):
        method = inspect.stack()[1][3]
        return self._monitor_manager.invoke(
            driver, method, **kwargs)

    def monitor_get_config(self, vnf_dict):
        return self._invoke(
            vnf_dict, monitor=self, vnf=vnf_dict)

    def monitor_url(self, vnf_dict):
        return self._invoke(
            vnf_dict, monitor=self, vnf=vnf_dict)

    def monitor_call(self, driver, vnf_dict, kwargs):
        return self._invoke(driver,
                            vnf=vnf_dict, kwargs=kwargs)


class VNFAlarmMonitor(object):
    """VNF Alarm monitor"""
    OPTS = [
        cfg.ListOpt(
            'alarm_monitor_driver', default=['ceilometer'],
            help=_('Alarm monitoring driver to communicate with '
                   'Hosting VNF/logical service '
                   'instance tacker plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'tacker')

    # get alarm here
    def __init__(self):
        self._alarm_monitor_manager = driver_manager.DriverManager(
            'tacker.tacker.alarm_monitor.drivers',
            cfg.CONF.tacker.alarm_monitor_driver)

    def update_vnf_with_alarm(self, vnf, policy_name, policy_dict):
        params = dict()
        params['vnf_id'] = vnf['id']
        params['mon_policy_name'] = policy_name
        _log_monitor_events(t_context.get_admin_context(),
                            vnf,
                            "update vnf with alarm")
        driver = policy_dict['triggers']['resize_compute'][
            'event_type']['implementation']
        policy_action = policy_dict['triggers']['resize_compute'].get('action')
        if not policy_action:
            return
        alarm_action_name = policy_action['resize_compute'].get('action_name')
        if not alarm_action_name:
            return
        params['mon_policy_action'] = alarm_action_name
        alarm_url = self.call_alarm_url(driver, vnf, params)
        _log_monitor_events(t_context.get_admin_context(),
                            vnf,
                            "Alarm url invoked")
        return alarm_url
        # vnf['attribute']['alarm_url'] = alarm_url ---> create
        # by plugin or vm_db

    def process_alarm_for_vnf(self, policy):
        '''call in plugin'''
        vnf = policy['vnf']
        params = policy['params']
        mon_prop = policy['properties']
        alarm_dict = dict()
        alarm_dict['alarm_id'] = params['data'].get('alarm_id')
        alarm_dict['status'] = params['data'].get('current')
        driver = mon_prop['resize_compute']['event_type']['implementation']
        return self.process_alarm(driver, vnf, alarm_dict)

    def _invoke(self, driver, **kwargs):
        method = inspect.stack()[1][3]
        return self._alarm_monitor_manager.invoke(
            driver, method, **kwargs)

    def call_alarm_url(self, driver, vnf_dict, kwargs):
        return self._invoke(driver,
                            vnf=vnf_dict, kwargs=kwargs)

    def process_alarm(self, driver, vnf_dict, kwargs):
        return self._invoke(driver,
                            vnf=vnf_dict, kwargs=kwargs)


@six.add_metaclass(abc.ABCMeta)
class ActionPolicy(object):
    @classmethod
    @abc.abstractmethod
    def execute_action(cls, plugin, vnf_dict):
        pass

    _POLICIES = {}

    @staticmethod
    def register(policy, infra_driver=None):
        def _register(cls):
            cls._POLICIES.setdefault(policy, {})[infra_driver] = cls
            return cls
        return _register

    @classmethod
    def get_policy(cls, policy, infra_driver=None):
        action_clses = cls._POLICIES.get(policy)
        if not action_clses:
            return None
        cls = action_clses.get(infra_driver)
        if cls:
            return cls
        return action_clses.get(None)

    @classmethod
    def get_supported_actions(cls):
        return cls._POLICIES.keys()


@ActionPolicy.register('respawn')
class ActionRespawn(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict):
        LOG.error(_('vnf %s dead'), vnf_dict['id'])
        if plugin._mark_vnf_dead(vnf_dict['id']):
            plugin._vnf_monitor.mark_dead(vnf_dict['id'])

            attributes = vnf_dict['attributes'].copy()
            attributes['dead_vnf_id'] = vnf_dict['id']
            new_vnf = {'attributes': attributes}
            for key in ('tenant_id', 'vnfd_id', 'name'):
                new_vnf[key] = vnf_dict[key]
            LOG.debug(_('new_vnf %s'), new_vnf)

            # keystone v2.0 specific
            authtoken = CONF.keystone_authtoken
            token = clients.OpenstackClients().auth_token

            context = t_context.get_admin_context()
            context.tenant_name = authtoken.project_name
            context.user_name = authtoken.username
            context.auth_token = token['id']
            context.tenant_id = token['tenant_id']
            context.user_id = token['user_id']
            _log_monitor_events(context, vnf_dict,
                                "ActionRespawnPolicy invoked")
            new_vnf_dict = plugin.create_vnf(context,
                                             {'vnf': new_vnf})
            _log_monitor_events(context, new_vnf_dict,
                                "ActionRespawnPolicy complete")
            LOG.info(_('respawned new vnf %s'), new_vnf_dict['id'])

############################ Cluster ##############################
@ActionPolicy.register('loadbalancer')
class ActionRespawn(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict):
        LOG.error(_('ActionRespawn loadbalancer vnf %s dead'), vnf_dict['id'])
        context = t_context.get_admin_context()
        nfvo_plugin = manager.TackerManager.get_service_plugins()['NFVO']
        newvnf_id = nfvo_plugin.recovery_action(context, vnf_dict['id'])
        LOG.debug(_('ActionRespawn loadbalancer newvnf : %s'), newvnf_id)
        

###################################################################

@ActionPolicy.register('respawn', 'openstack')
class ActionRespawnHeat(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict):
        start_time = time.time()
        vnf_id = vnf_dict['id']
        LOG.info(_('vnf %s is dead and needs to be respawned'), vnf_id)
        attributes = vnf_dict['attributes']
        vim_id = vnf_dict['vim_id']
        # TODO(anyone) set the current request ctxt
        context = t_context.get_admin_context()

        def _update_failure_count():
            failure_count = int(attributes.get('failure_count', '0')) + 1
            failure_count_str = str(failure_count)
            LOG.debug(_("vnf %(vnf_id)s failure count %(failure_count)s") %
                      {'vnf_id': vnf_id, 'failure_count': failure_count_str})
            attributes['failure_count'] = failure_count_str
            attributes['dead_instance_id_' + failure_count_str] = vnf_dict[
                'instance_id']

        def _fetch_vim(vim_uuid):
            return vim_client.VimClient().get_vim(context, vim_uuid)

        def _delete_heat_stack(vim_auth):
            placement_attr = vnf_dict.get('placement_attr', {})
            region_name = placement_attr.get('region_name')
            heatclient = openstack.HeatClient(auth_attr=vim_auth,
                                              region_name=region_name)
            heatclient.delete(vnf_dict['instance_id'])
            LOG.debug(_("Heat stack %s delete initiated"), vnf_dict[
                'instance_id'])
            _log_monitor_events(context, vnf_dict, "ActionRespawnHeat invoked")

        def _respin_vnf():
            update_vnf_dict = plugin.create_vnf_sync(context, vnf_dict)
            LOG.info(_('respawned new vnf %s'), update_vnf_dict['id'])
            plugin.config_vnf(context, update_vnf_dict)
            return update_vnf_dict

        if plugin._mark_vnf_dead(vnf_dict['id']):
            _update_failure_count()
            vim_res = _fetch_vim(vim_id)
            if vnf_dict['attributes'].get('monitoring_policy'):
                plugin._vnf_monitor.mark_dead(vnf_dict['id'])
                _delete_heat_stack(vim_res['vim_auth'])
                updated_vnf = _respin_vnf()
                plugin.add_vnf_to_monitor(updated_vnf, vim_res['vim_type'])
                LOG.debug(_("VNF %s added to monitor thread"), updated_vnf[
                    'id'])
            if vnf_dict['attributes'].get('alarm_url'):
                _delete_heat_stack(vim_res['vim_auth'])
                vnf_dict['attributes'].pop('alarm_url')
                _respin_vnf()
        end_time = time.time()
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("ActionRespawnHeat Time Result : %s"), end_time-start_time)
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.error(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))


@ActionPolicy.register('scaling')
class ActionAutoscalingHeat(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict, scale):
        vnf_id = vnf_dict['id']
        plugin.create_vnf_scale(t_context.get_admin_context(), vnf_id, scale)
        _log_monitor_events(t_context.get_admin_context(),
                            vnf_dict,
                            "ActionAutoscalingHeat invoked")


@ActionPolicy.register('log')
class ActionLogOnly(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict):
        vnf_id = vnf_dict['id']
        LOG.error(_('vnf %s dead'), vnf_id)
        _log_monitor_events(t_context.get_admin_context(),
                            vnf_dict,
                            "ActionLogOnly invoked")


@ActionPolicy.register('log_and_kill')
class ActionLogAndKill(ActionPolicy):
    @classmethod
    def execute_action(cls, plugin, vnf_dict):
        _log_monitor_events(t_context.get_admin_context(),
                            vnf_dict,
                            "ActionLogAndKill invoked")
        vnf_id = vnf_dict['id']
        if plugin._mark_vnf_dead(vnf_dict['id']):
            if vnf_dict['attributes'].get('monitoring_policy'):
                plugin._vnf_monitor.mark_dead(vnf_dict['id'])
            plugin.delete_vnf(t_context.get_admin_context(), vnf_id)
        LOG.error(_('vnf %s dead'), vnf_id)
