# Copyright 2016 Brocade Communications System, Inc.
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

import os
import threading
import time
import uuid
import yaml

from cryptography import fernet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import strutils

from tacker._i18n import _
from tacker.common import driver_manager
from tacker.common import exceptions
from tacker.common import log
from tacker.common import utils
from tacker import context as t_context
from tacker.db.nfvo import nfvo_db
from tacker.db.nfvo import vnffg_db
from tacker.extensions import nfvo
from tacker import manager
from tacker.plugins.common import constants
from tacker.vnfm.tosca import utils as toscautils
from toscaparser import tosca_template


LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def config_opts():
    return [('nfvo', NfvoPlugin.OPTS)]


class NfvoPlugin(nfvo_db.NfvoPluginDb, vnffg_db.VnffgPluginDbMixin):
    """NFVO reference plugin for NFVO extension

    Implements the NFVO extension and defines public facing APIs for VIM
    operations. NFVO internally invokes the appropriate VIM driver in
    backend based on configured VIM types. Plugin also interacts with VNFM
    extension for providing the specified VIM information
    """
    supported_extension_aliases = ['nfvo']
    _lock = threading.RLock()

    OPTS = [
        cfg.ListOpt(
            'vim_drivers', default=['openstack'],
            help=_('VIM driver for launching VNFs')),
        cfg.IntOpt(
            'monitor_interval', default=30,
            help=_('Interval to check for VIM health')),
    ]
    cfg.CONF.register_opts(OPTS, 'nfvo_vim')

    def __init__(self):
        super(NfvoPlugin, self).__init__()
        self._vim_drivers = driver_manager.DriverManager(
            'tacker.nfvo.vim.drivers',
            cfg.CONF.nfvo_vim.vim_drivers)
        self._created_vims = dict()
        context = t_context.get_admin_context()
        vims = self.get_vims(context)
        for vim in vims:
            self._created_vims[vim["id"]] = vim
        self._monitor_interval = cfg.CONF.nfvo_vim.monitor_interval
        threading.Thread(target=self.__run__).start()

    def __run__(self):
        while(1):
            time.sleep(self._monitor_interval)
            for created_vim in self._created_vims.values():
                self.monitor_vim(created_vim)

    @log.log
    def create_vim(self, context, vim):
        LOG.debug(_('Create vim called with parameters %s'),
             strutils.mask_password(vim))
        vim_obj = vim['vim']
        name = vim_obj['name']
        if self._get_by_name(context, nfvo_db.Vim, name):
            raise exceptions.DuplicateResourceName(resource='VIM', name=name)
        vim_type = vim_obj['type']
        vim_obj['id'] = str(uuid.uuid4())
        vim_obj['status'] = 'PENDING'
        try:
            self._vim_drivers.invoke(vim_type, 'register_vim', vim_obj=vim_obj)
            res = super(NfvoPlugin, self).create_vim(context, vim_obj)
            vim_obj["status"] = "REGISTERING"
            with self._lock:
                self._created_vims[res["id"]] = res
            self.monitor_vim(vim_obj)
            return res
        except Exception:
            with excutils.save_and_reraise_exception():
                self._vim_drivers.invoke(vim_type, 'delete_vim_auth',
                                         vim_id=vim_obj['id'])

    def _get_vim(self, context, vim_id):
        if not self.is_vim_still_in_use(context, vim_id):
            return self.get_vim(context, vim_id)

    @log.log
    def update_vim(self, context, vim_id, vim):
        vim_obj = self._get_vim(context, vim_id)
        utils.deep_update(vim_obj, vim['vim'])
        vim_type = vim_obj['type']
        try:
            self._vim_drivers.invoke(vim_type, 'register_vim', vim_obj=vim_obj)
            return super(NfvoPlugin, self).update_vim(context, vim_id, vim_obj)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._vim_drivers.invoke(vim_type, 'delete_vim_auth',
                                         vim_id=vim_obj['id'])

    @log.log
    def delete_vim(self, context, vim_id):
        vim_obj = self._get_vim(context, vim_id)
        self._vim_drivers.invoke(vim_obj['type'], 'deregister_vim',
                                 vim_id=vim_id)
        with self._lock:
            self._created_vims.pop(vim_id, None)
        super(NfvoPlugin, self).delete_vim(context, vim_id)

    @log.log
    def monitor_vim(self, vim_obj):
        vim_id = vim_obj["id"]
        auth_url = vim_obj["auth_url"]
        vim_status = self._vim_drivers.invoke(vim_obj['type'],
                                              'vim_status',
                                              auth_url=auth_url)
        current_status = "REACHABLE" if vim_status else "UNREACHABLE"
        if current_status != vim_obj["status"]:
            status = current_status
            with self._lock:
                context = t_context.get_admin_context()
                res = super(NfvoPlugin, self).update_vim_status(context,
                    vim_id, status)
                self._created_vims[vim_id]["status"] = status
                self._cos_db_plg.create_event(
                    context, res_id=res['id'],
                    res_type=constants.RES_TYPE_VIM,
                    res_state=res['status'],
                    evt_type=constants.RES_EVT_MONITOR,
                    tstamp=res[constants.RES_EVT_UPDATED_FLD])

    @log.log
    def validate_tosca(self, template):
        if "tosca_definitions_version" not in template:
            raise nfvo.ToscaParserFailed(
                error_msg_details='tosca_definitions_version missing in '
                                  'template'
            )

        LOG.debug(_('template yaml: %s'), template)

        toscautils.updateimports(template)

        try:
            tosca_template.ToscaTemplate(
                a_file=False, yaml_dict_tpl=template)
        except Exception as e:
            LOG.exception(_("tosca-parser error: %s"), str(e))
            raise nfvo.ToscaParserFailed(error_msg_details=str(e))

    @log.log
    def create_vnffgd(self, context, vnffgd):
        template = vnffgd['vnffgd']

        if 'vnffgd' not in template.get('template'):
            raise nfvo.VnffgdInvalidTemplate(template=template.get('template'))
        else:
            self.validate_tosca(template['template']['vnffgd'])
            temp = template['template']['vnffgd']['topology_template']
            vnffg_name = list(temp['groups'].keys())[0]
            nfp_name = temp['groups'][vnffg_name]['members'][0]
            path = self._get_nfp_attribute(template['template'], nfp_name,
                                           'path')
            prev_element = None
            known_forwarders = set()
            for element in path:
                if element.get('forwarder') in known_forwarders:
                    if prev_element is not None and element.get('forwarder')\
                            != prev_element['forwarder']:
                        raise nfvo.VnffgdDuplicateForwarderException(
                            forwarder=element.get('forwarder')
                        )
                    elif prev_element is not None and element.get(
                            'capability') == prev_element['capability']:
                        raise nfvo.VnffgdDuplicateCPException(
                            cp=element.get('capability')
                        )
                else:
                    known_forwarders.add(element.get('forwarder'))
                prev_element = element
        return super(NfvoPlugin, self).create_vnffgd(context, vnffgd)

    @log.log
    def create_vnffg(self, context, vnffg):
        vnffg_dict = super(NfvoPlugin, self)._create_vnffg_pre(context, vnffg)
        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])
        match = super(NfvoPlugin, self).get_classifier(context,
                                                       nfp['classifier_id'],
                                                       fields='match')['match']
        # grab the first VNF to check it's VIM type
        # we have already checked that all VNFs are in the same VIM
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        # TODO(trozet): figure out what auth info we actually need to pass
        # to the driver.  Is it a session, or is full vim obj good enough?
        driver_type = vim_obj['type']
        try:
            fc_id = self._vim_drivers.invoke(driver_type,
                                             'create_flow_classifier',
                                             name=vnffg_dict['name'],
                                             fc=match,
                                             auth_attr=vim_obj['auth_cred'],
                                             symmetrical=sfc['symmetrical'])
            sfc_id = self._vim_drivers.invoke(driver_type,
                                              'create_chain',
                                              name=vnffg_dict['name'],
                                              vnfs=sfc['chain'], fc_id=fc_id,
                                              symmetrical=sfc['symmetrical'],
                                              auth_attr=vim_obj['auth_cred'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.delete_vnffg(context, vnffg_id=vnffg_dict['id'])
        super(NfvoPlugin, self)._create_vnffg_post(context, sfc_id, fc_id,
                                                   vnffg_dict)
        super(NfvoPlugin, self)._create_vnffg_status(context, vnffg_dict)
        return vnffg_dict

    @log.log
    def update_vnffg(self, context, vnffg_id, vnffg):
        vnffg_dict = super(NfvoPlugin, self)._update_vnffg_pre(context,
                                                               vnffg_id)
        new_vnffg = vnffg['vnffg']
        LOG.debug(_('vnffg update: %s'), vnffg)
        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])

        fc = super(NfvoPlugin, self).get_classifier(context,
                                                    nfp['classifier_id'])
        template_db = self._get_resource(context, vnffg_db.VnffgTemplate,
                                         vnffg_dict['vnffgd_id'])
        vnf_members = self._get_vnffg_property(template_db,
                                               'constituent_vnfs')
        new_vnffg['vnf_mapping'] = super(NfvoPlugin, self)._get_vnf_mapping(
            context, new_vnffg.get('vnf_mapping'), vnf_members)
        template_id = vnffg_dict['vnffgd_id']
        template_db = self._get_resource(context, vnffg_db.VnffgTemplate,
                                         template_id)
        # functional attributes that allow update are vnf_mapping,
        # and symmetrical.  Therefore we need to figure out the new chain if
        # it was updated by new vnf_mapping.  Symmetrical is handled by driver.

        chain = super(NfvoPlugin, self)._create_port_chain(context,
                                                           new_vnffg[
                                                               'vnf_mapping'],
                                                           template_db,
                                                           nfp['name'])
        LOG.debug(_('chain update: %s'), chain)
        sfc['chain'] = chain
        sfc['symmetrical'] = new_vnffg['symmetrical']
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        driver_type = vim_obj['type']
        try:
            # we don't support updating the match criteria in first iteration
            # so this is essentially a noop.  Good to keep for future use
            # though.
            self._vim_drivers.invoke(driver_type, 'update_flow_classifier',
                                     fc_id=fc['instance_id'], fc=fc['match'],
                                     auth_attr=vim_obj['auth_cred'],
                                     symmetrical=new_vnffg['symmetrical'])
            self._vim_drivers.invoke(driver_type, 'update_chain',
                                     vnfs=sfc['chain'],
                                     fc_ids=[fc['instance_id']],
                                     chain_id=sfc['instance_id'],
                                     auth_attr=vim_obj['auth_cred'],
                                     symmetrical=new_vnffg['symmetrical'])
        except Exception:
            with excutils.save_and_reraise_exception():
                vnffg_dict['status'] = constants.ERROR
                super(NfvoPlugin, self)._update_vnffg_post(context, vnffg_id,
                                                           constants.ERROR)
        super(NfvoPlugin, self)._update_vnffg_post(context, vnffg_id,
                                                   constants.ACTIVE, new_vnffg)
        # update chain
        super(NfvoPlugin, self)._update_sfc_post(context, sfc['id'],
                                                 constants.ACTIVE, sfc)
        # update classifier - this is just updating status until functional
        # updates are supported to classifier
        super(NfvoPlugin, self)._update_classifier_post(context, fc['id'],
                                                        constants.ACTIVE)
        return vnffg_dict

    @log.log
    def delete_vnffg(self, context, vnffg_id):
        vnffg_dict = super(NfvoPlugin, self)._delete_vnffg_pre(context,
                                                               vnffg_id)
        nfp = super(NfvoPlugin, self).get_nfp(context,
                                              vnffg_dict['forwarding_paths'])
        sfc = super(NfvoPlugin, self).get_sfc(context, nfp['chain_id'])

        fc = super(NfvoPlugin, self).get_classifier(context,
                                                    nfp['classifier_id'])
        vim_obj = self._get_vim_from_vnf(context,
                                         list(vnffg_dict[
                                              'vnf_mapping'].values())[0])
        driver_type = vim_obj['type']
        try:
            if sfc['instance_id'] is not None:
                self._vim_drivers.invoke(driver_type, 'delete_chain',
                                         chain_id=sfc['instance_id'],
                                         auth_attr=vim_obj['auth_cred'])
            if fc['instance_id'] is not None:
                self._vim_drivers.invoke(driver_type,
                                         'delete_flow_classifier',
                                         fc_id=fc['instance_id'],
                                         auth_attr=vim_obj['auth_cred'])
        except Exception:
            with excutils.save_and_reraise_exception():
                vnffg_dict['status'] = constants.ERROR
                super(NfvoPlugin, self)._delete_vnffg_post(context, vnffg_id,
                                                           True)
        super(NfvoPlugin, self)._delete_vnffg_post(context, vnffg_id, False)
        return vnffg_dict

    def _get_vim_from_vnf(self, context, vnf_id):
        """Figures out VIM based on a VNF

        :param context: SQL Session Context
        :param vnf_id: VNF ID
        :return: VIM or VIM properties if fields are provided
        """
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        vim_id = vnfm_plugin.get_vnf(context, vnf_id, fields=['vim_id'])
        vim_obj = self.get_vim(context, vim_id['vim_id'], mask_password=False)
        vim_auth = vim_obj['auth_cred']
        vim_auth['password'] = self._decode_vim_auth(vim_obj['id'],
                                                     vim_auth['password'].
                                                     encode('utf-8'))
        vim_auth['auth_url'] = vim_obj['auth_url']
        if vim_obj is None:
            raise nfvo.VimFromVnfNotFoundException(vnf_id=vnf_id)

        return vim_obj

    def _decode_vim_auth(self, vim_id, cred):
        """Decode Vim credentials

        Decrypt VIM cred. using Fernet Key
        """
        vim_key = self._find_vim_key(vim_id)
        f = fernet.Fernet(vim_key)
        if not f:
            LOG.warning(_('Unable to decode VIM auth'))
            raise nfvo.VimNotFoundException('Unable to decode VIM auth key')
        return f.decrypt(cred)

    @staticmethod
    def _find_vim_key(vim_id):
        key_file = os.path.join(CONF.vim_keys.openstack, vim_id)
        LOG.debug(_('Attempting to open key file for vim id %s'), vim_id)
        with open(key_file, 'r') as f:
                return f.read()
        LOG.warning(_('VIM id invalid or key not found for  %s'), vim_id)

    def _vim_resource_name_to_id(self, context, resource, name, vnf_id):
        """Converts a VIM resource name to its ID

        :param resource: resource type to find (network, subnet, etc)
        :param name: name of the resource to find its ID
        :param vnf_id: A VNF instance ID that is part of the chain to which
               the classifier will apply to
        :return: ID of the resource name
        """
        vim_obj = self._get_vim_from_vnf(context, vnf_id)
        driver_type = vim_obj['type']
        return self._vim_drivers.invoke(driver_type,
                                        'get_vim_resource_id',
                                        vim_auth=vim_obj['auth_cred'],
                                        resource_type=resource,
                                        resource_name=name)

    ############################################################################################

    def recovery_action(self, context, vnf_id):
        def _create_new_vnf_cluster(context, cluster_name, vnf_id):
            def _make_vnf_name(cluster_name):
                cluster_instance = str(uuid.uuid4())
                return cluster_name + '-vnf-' + cluster_instance
            
            vnf = vnfm_plugin.get_vnf(context, vnf_id)
            vnfd_dict = yaml.load(vnf['vnfd']['attributes']['vnfd'])
            LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
            LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
            LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
            vnf_info = {}
            vnf_info['tenant_id'] = vnf['tenant_id']
            vnf_info['vnfd_id'] = vnf['vnfd_id']
            vnf_name = _make_vnf_name(cluster_name)
            pre_vnf_dict = self._make_vnf_create_dict(vnf_info, vnf_name)
            LOG.debug(_("_create_new_vnf_cluster vnfd_dict : %s"), vnfd_dict)
            LOG.debug(_("_create_new_vnf_cluster vnf : %s"), vnf)
            vnf_dict = vnfm_plugin.create_vnf(context, pre_vnf_dict)
            ## Need to find appropriate Func to wait for creating VNF
            while(1):
                LOG.debug(_("create_vnfcluster new_vnf_dict.get('status'): %s"), vnf_dict.get('status'))
                if vnf_dict.get('status') == 'ACTIVE':
                    break
                time.sleep(4)
            return vnf_dict
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("recovery_action !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))

        LOG.debug(_("recovery_action vnf_id : %s"), vnf_id)
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        vnf = vnfm_plugin.get_vnf(context, vnf_id)
        vnfd_dict = yaml.load(vnf['vnfd']['attributes']['vnfd'])
        target_list = self._get_policy_property(vnfd_dict, 'targets')
        
        start_time = time.time()
        vnfclustermembers = self.get_vnfclustermembers(context)
        LOG.debug(_("recovery_action vnfclustermember : %s"), vnfclustermembers)
        port_id = None
        cluster_id = None
        member_id = None
        fault_member = None
        fault_lb_member_id = None
        for member in vnfclustermembers:
            if member['vnf_info']['vnf_id'] == vnf_id:
                fault_member = member['id']
                fault_lb_member_id = member['lb_member_id']
                LOG.error(_("This member is Fault : %s"), member['id'])
            if member['role'] == 'STANDBY':
                LOG.debug(_("STNADBY vnfmember : %s"), member['id'])
                LOG.debug(_("STNADBY vnfmember [port_id] : %s"), member['vnf_info']['port_id'])
                cluster_id = member['cluster_id']
                port_id = member['vnf_info']['port_id']
                member_id = member['id']
        vnfcluster = self.get_vnfcluster(context, cluster_id)
        LOG.debug(_("recovery_action vnfcluster : %s"), vnfcluster)
        vim_obj = self._get_vim_from_vnf(context,
                                         member['vnf_info']['vnf_id'])
        driver_type = vim_obj['type']
        lb_result = vnfcluster['policy_info']['loadbalancer']
        lb_member_id = self._vim_drivers.invoke(driver_type, 'pool_member_add',
                                                net_port_id=port_id,
                                                lb_info=lb_result,
                                                auth_attr=vim_obj['auth_cred'])
        
        end_time = time.time()
        LOG.debug(_("Total Time : %s"), end_time-start_time)
        

        self._update_member_lb_id(context, member_id, lb_member_id)        

        ha_result = vnfcluster['policy_info']['ha_cluster']
        self._update_member_role(context, member_id, 'ACTIVE')
        new_vnf_dict = _create_new_vnf_cluster(context, vnfcluster['name'], vnf_id)
        
        vnf_resource = vnfm_plugin.get_vnf_resources(context, new_vnf_dict.get('id'))
        vnf_info = {}
        vnf_cp = list()
        vnf_info['vnf_id'] = new_vnf_dict['id']
        vnf_info['vm_id'] = new_vnf_dict['instance_id']
        for resource in vnf_resource:
            if resource['name'] in target_list:
                vnf_cp.append(resource['id'])
                break
        vnf_info['port_id'] = vnf_cp[0]
        cluster_member_dict = self._make_cluster_member_dict(cluster_id, 3, 'STANDBY', vnf_info)
        cluster_member_info = self._create_cluster_member(context, cluster_member_dict)        
        
        self._vim_drivers.invoke(driver_type, 'pool_member_remove',
                                 lb_id=lb_result['loadbalancer'],
                                 pool_id=lb_result['pool'],
                                 member_id=fault_lb_member_id,
                                 auth_attr=vim_obj['auth_cred'])
        self.delete_vnfclustermember(context, fault_member)
        vnfm_plugin.delete_vnf(context, vnf_id)

        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))

    def _make_vnf_create_dict(self, cluster, name):
        vnf_dict = {}
        c = {}
        c['description'] = ''
        c['tenant_id'] = cluster['tenant_id']
        c['vim_id'] = ''
        c['name'] = name
        c['placement_attr'] = {}
        c['attributes'] = {}
        c['vnfd_id'] = cluster['vnfd_id']
        vnf_dict['vnf'] = c
        LOG.debug(_("_make_policy_dict c : %s"), c)
        return vnf_dict

    def _create_cluster(self, context, cluster):
        cluster_dict = self._create_cluster_pre(context, cluster)
        LOG.debug(_('vnf_dict %s'), cluster_dict)
        return cluster_dict

    def _create_cluster_member(self, context, cluster_member):
        cluster_member_dict = self._create_cluster_member_pre(context, cluster_member)
        LOG.debug(_('cluster_member_dict %s'), cluster_member_dict)
        return cluster_member_dict

    def _make_cluster_member_dict(self, cluster_id, index, role, vnf_info):
        cluster_member_dict = {}
        cluster_member_dict['cluster_id'] = cluster_id
        cluster_member_dict['index'] = index
        cluster_member_dict['role'] = role
        cluster_member_dict['vnf_info'] = vnf_info
        LOG.debug(_("_make_cluster_member_dict c : %s"), cluster_member_dict)
        return cluster_member_dict
    
    def _get_policy_property(self, vnfd_dict, prop_name):
            polices = vnfd_dict['topology_template'].get('policies', [])
            prop = None
            for policy_dict in polices:
                for name, policy in policy_dict.items():
                    if(policy.get('type') == constants.POLICY_LOADBALANCE):
                        prop = policy.get('properties')[prop_name]
                        LOG.debug(_("create_vnfcluster prop: %s"), prop)
            return prop

    @log.log
    def create_vnfcluster(self, context, vnfcluster):

        
        def _create_vnf_cluster(cluster):
            def _make_vnf_name(cluster_name):
                cluster_instance = str(uuid.uuid4())
                return cluster_name + '-vnf-' + cluster_instance
            
            cluster_name = _make_vnf_name(cluster['name'])
            pre_vnf_dict = self._make_vnf_create_dict(cluster, cluster_name)
            vnf_dict = vnfm_plugin.create_vnf(context, pre_vnf_dict)
            ## Need to find appropriate Func to wait for creating VNF
            while(1):
                LOG.debug(_("create_vnfcluster new_vnf_dict.get('status'): %s"), vnf_dict.get('status'))
                if vnf_dict.get('status') == 'ACTIVE':
                    break
                time.sleep(4)
            return vnf_dict
        


        cluster_info = vnfcluster['vnfcluster']
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        vnfd = vnfm_plugin.get_vnfd(context, cluster_info['vnfd_id'])
        vnfd_dict = yaml.load(vnfd['attributes']['vnfd'])
        target_list = self._get_policy_property(vnfd_dict, 'targets')
        ha_policy = {}
        ha_prop = None
        node_template = vnfd_dict['topology_template'].get('node_templates', [])
        for node in node_template:
            if node_template[node]['type'] == 'tosca.nodes.nfv.VDU.Tacker':
                ha_prop = node_template[node]['capabilities']['nfv_ha_cluster']['properties']
        if ha_prop:
            ha_policy['ha_cluster'] = ha_prop
        vnf_dict = None
        vnf_cp = list()
        active = int(cluster_info['active'])
        standby = int(cluster_info['standby'])

        # 1. Create DB(Cluster)
        cluster_dict = self._create_cluster(context, vnfcluster)
        cluster_id = cluster_dict['id']
        
        # 2. Create ACTIVE VNF
        member_id_list = []
        for index in xrange(active):
            vnf_dict = _create_vnf_cluster(cluster_info)
            vnf_resource = vnfm_plugin.get_vnf_resources(context, vnf_dict.get('id'))
            vnf_info = {}
            vnf_info['vnf_id'] = vnf_dict['id']
            vnf_info['vm_id'] = vnf_dict['instance_id']
            for resource in vnf_resource:
                if resource['name'] in target_list:
                    vnf_cp.append(resource['id'])
                    break
            vnf_info['port_id'] = vnf_cp[index]
            cluster_member_dict = self._make_cluster_member_dict(cluster_id, index, 'ACTIVE', vnf_info)
            cluster_member_info = self._create_cluster_member(context, cluster_member_dict)
            member_id_list.append(cluster_member_info['id'])

        # 3. Create STANBY VNF and DB(Cluster Member)
        for index in xrange(active, active+standby):  
            vnf_dict = _create_vnf_cluster(cluster_info)
            vnf_resource = vnfm_plugin.get_vnf_resources(context, vnf_dict.get('id'))
            vnf_info = {}
            vnf_info['vnf_id'] = vnf_dict['id']
            vnf_info['vm_id'] = vnf_dict['instance_id']
            for resource in vnf_resource:
                if resource['name'] in target_list:
                    vnf_cp.append(resource['id'])
                    break
            vnf_info['port_id'] = vnf_cp[index]
            cluster_member_dict = self._make_cluster_member_dict(cluster_id, index, 'STANDBY', vnf_info)
            self._create_cluster_member(context, cluster_member_dict)


        # 4. Create Load-balancer for cluster
        lb_pool = self._get_policy_property(vnfd_dict, 'pool')
        lb_vip = self._get_policy_property(vnfd_dict, 'vip')
        vim_obj = self._get_vim_from_vnf(context,
                                         vnf_dict.get('id'))
        driver_type = vim_obj['type']
        lb_result = self._vim_drivers.invoke(driver_type, 'create_loadbalancer',
                                             lb_pool=lb_pool,
                                             lb_vip=lb_vip,
                                             auth_attr=vim_obj['auth_cred'])
        
        ha_policy['loadbalancer'] = lb_result
        self._update_ha_policy(context, cluster_id, ha_policy)
        #self._update_lb_policy(context, cluster_id, lb_result)
        for index in xrange(active):
            lb_member_id = self._vim_drivers.invoke(driver_type, 'pool_member_add',
                                                    net_port_id=vnf_cp[index],
                                                    lb_info=lb_result,
                                                    auth_attr=vim_obj['auth_cred'])
            LOG.debug(_("create_vnfcluster member_result : %s"), lb_member_id)
            self._update_member_lb_id(context, member_id_list[index], lb_member_id)


        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))

        LOG.debug(_("create_vnfcluster lb_result : %s"), lb_result)
        LOG.debug(_("create_vnfcluster vnfcluster : %s"), vnfcluster)
        LOG.debug(_("create_vnfcluster cluster_dict : %s"), cluster_dict)
        LOG.debug(_("create_vnfcluster vnfd : %s"), vnfd)
        LOG.debug(_("create_vnfcluster vnfd_dict: %s"), vnfd_dict)
        LOG.debug(_("create_vnfcluster vnf_cp: %s"), vnf_cp)
        LOG.debug(_("create_vnfcluster target_list: %s"), target_list)
        LOG.debug(_("create_vnfcluster cluster_id: %s"), cluster_id)
        LOG.debug(_("create_vnfcluster driver_type: %s"), driver_type)
        LOG.debug(_("create_vnfcluster vim_obj: %s"), vim_obj)

        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        LOG.debug(_("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"))
        # cluster_dict['loadbalancer'] = lb_result
        return cluster_dict
